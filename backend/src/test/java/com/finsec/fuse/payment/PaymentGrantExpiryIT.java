package com.finsec.fuse.payment;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.policy.DelegationService;
import com.finsec.fuse.policy.GrantCodec;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;

/** Payment grants have the earlier trusted approval deadline and 60-second start window. */
class PaymentGrantExpiryIT extends PaymentFixture {
    @Autowired DelegationService grants;
    @Autowired GrantCodec codec;
    @Autowired FusePolicy policy;

    @ParameterizedTest @ValueSource(ints={30,60,600})
    void paymentGrantClaimsAndRegistryUseTheEarlierDeadline(int approvalSecondsRemaining) {
        UUID workflowId=ready102();var pay=approve(workflowId);Instant issuedAt=clock.now();
        Instant approvalExpiresAt=issuedAt.plusSeconds(approvalSecondsRemaining);
        tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflowId);
            db.update("UPDATE approval SET expires_at=? WHERE id=(SELECT approval_id FROM workflow_job WHERE id=?)",approvalExpiresAt,pay.jobId());
        });
        assertEquals("PAYMENT_RESERVED",payments.reserve(pay.jobId(),pay.token()).get("state"));
        var grant=paymentGrant(workflowId);var verified=codec.verify(grants.transport(uuid(grant,"id")));
        Instant expected=issuedAt.plusSeconds(Math.min(approvalSecondsRemaining,60));
        assertEquals(expected,instant(grant,"expires_at"));
        assertEquals(expected.toEpochMilli(),verified.claims().expiresAtEpochMs());
        assertEquals(uuid(db.required("SELECT approval_id FROM workflow_job WHERE id=?",pay.jobId()),"approval_id"),verified.claims().approvalId());
        assertRisk(workflowId,35,50);assertEquals(0,count("mock_payment"));
        clock.set(expected.minusMillis(1));
        assertEquals("PAID",payments.commit(pay.jobId(),pay.token()).get("state"));
        assertEquals(1,count("mock_payment"));assertRisk(workflowId,85,0);
    }
    @ParameterizedTest @ValueSource(ints={30,600})
    void exactDeadlineReleasesReservationWithoutPaymentOrRefreshingTheAction(int approvalSecondsRemaining) {
        UUID workflowId=ready102();var pay=approve(workflowId);Instant issuedAt=clock.now();
        tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflowId);
            db.update("UPDATE approval SET expires_at=? WHERE id=(SELECT approval_id FROM workflow_job WHERE id=?)",issuedAt.plusSeconds(approvalSecondsRemaining),pay.jobId());
        });
        payments.reserve(pay.jobId(),pay.token());var original=paymentGrant(workflowId);
        Instant deadline=issuedAt.plusSeconds(Math.min(approvalSecondsRemaining,60));clock.set(deadline);
        var result=payments.commit(pay.jobId(),pay.token());
        assertEquals("WAIT_APPROVAL",result.get("state"));
        assertEquals(List.of(approvalSecondsRemaining<60?"APPROVAL_REQUIRED":"GRANT_EXPIRED"),result.get("reasonCodes"));
        assertRisk(workflowId,35,0);assertEquals(0,count("mock_payment"));assertEquals(0,count("quarantine"));
        assertEquals(1,events("RELEASE"));assertEquals(0,events("CONSUME"));
        assertEquals("WAIT_APPROVAL",payments.reserve(pay.jobId(),pay.token()).get("state"));
        var unchanged=paymentGrant(workflowId);
        assertEquals(uuid(original,"id"),uuid(unchanged,"id"));
        assertEquals(original.get("action_id"),unchanged.get("action_id"));
        assertEquals(deadline,instant(unchanged,"expires_at"));assertEquals("EXPIRED",str(unchanged,"status"));
        assertEquals(1,((Number)db.required("SELECT count(*) n FROM delegation_grant WHERE workflow_id=? AND target_agent='PAYMENT'",workflowId).get("n")).intValue());
    }
    @Test void kycAndLoanKeepTheirNormalPolicyTtlWithoutAnApproval() {
        Instant issuedAt=clock.now();UUID workflowId=ready102();
        var issued=db.query("SELECT * FROM delegation_grant WHERE workflow_id=? ORDER BY depth",workflowId);
        assertEquals(List.of("KYC","LOAN"),issued.stream().map(g->str(g,"target_agent")).toList());
        for(var grant:issued) {
            assertNull(grant.get("approval_id"));
            assertEquals(issuedAt.plusSeconds(policy.grantTtlSeconds()),instant(grant,"expires_at"));
            assertEquals(issuedAt.plusSeconds(policy.grantTtlSeconds()).toEpochMilli(),codec.verify(grants.transport(uuid(grant,"id"))).claims().expiresAtEpochMs());
        }
        assertEquals(0,count("approval"));assertEquals(0,count("mock_payment"));
    }
    private Map<String,Object> paymentGrant(UUID workflowId) {
        return db.required("SELECT * FROM delegation_grant WHERE workflow_id=? AND target_agent='PAYMENT'",workflowId);
    }
}
