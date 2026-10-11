package com.finsec.fuse.payment;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class WorkerRestartIT extends PaymentFixture {
    @Test void abandonedPaymentReservationExpiresToFreshApprovalWithoutReissuingGrant() {
        UUID workflowId=ready102();var pay=approve(workflowId);payments.reserve(pay.jobId(),pay.token());
        UUID oldGrant=uuid(db.required("select grant_id from payment_reservation where job_id=?",pay.jobId()),"grant_id");
        clock.set(clock.now().plusSeconds(91));payments.reap(pay.jobId());
        assertEquals("WAIT_APPROVAL",str(workflow(workflowId),"state"));assertRisk(workflowId,35,0);assertEquals(1,events("RELEASE"));assertEquals(0,count("mock_payment"));
        assertEquals("EXPIRED",str(db.required("select status from delegation_grant where id=?",oldGrant),"status"));
        payments.reap(pay.jobId());paymentAgent.execute(pay.jobId(),pay.token());assertEquals(1,events("RELEASE"));assertEquals(0,count("mock_payment"));
        var fresh=approve(workflowId);assertNotEquals(pay.jobId(),fresh.jobId());paymentAgent.execute(fresh.jobId(),fresh.token());
        assertEquals("PAID",str(workflow(workflowId),"state"));assertRisk(workflowId,85,0);assertEquals(1,count("mock_payment"));
        assertEquals(2,events("RESERVE"));assertEquals(1,events("CONSUME"));
    }
    @Test void aFailureAfterLedgerInsertRollsBackEveryPaymentChangeAndCanRetrySafely() {
        UUID workflowId=ready102();var pay=approve(workflowId);payments.reserve(pay.jobId(),pay.token());
        db.jdbc().execute("create function fail_test_payment_audit() returns trigger language plpgsql as $$ begin if NEW.event_type='PAYMENT_COMMITTED' then raise exception 'injected transactional write failure'; end if; return NEW; end; $$");
        db.jdbc().execute("create trigger fail_test_payment_audit before insert on audit_event for each row execute function fail_test_payment_audit()");
        assertThrows(org.springframework.dao.DataAccessException.class,()->payments.commit(pay.jobId(),pay.token()));
        assertEquals(0,count("mock_payment"));assertEquals(0,events("CONSUME"));assertRisk(workflowId,35,50);
        assertEquals("RESERVED",str(db.required("select * from approval where id=(select approval_id from workflow_job where id=?)",pay.jobId()),"status"));
        assertEquals("RUNNING",str(db.required("select * from workflow_job where id=?",pay.jobId()),"state"));
        db.jdbc().execute("drop trigger fail_test_payment_audit on audit_event");db.jdbc().execute("drop function fail_test_payment_audit()");
        assertEquals("PAID",payments.commit(pay.jobId(),pay.token()).get("state"));assertEquals(1,count("mock_payment"));assertEquals(1,events("CONSUME"));assertRisk(workflowId,85,0);
    }
    @Test void expiredJobBeforeReserveHasNoReleaseLedgerEntry() {
        UUID workflowId=ready102();var pay=approve(workflowId);clock.set(clock.now().plusSeconds(91));payments.reap(pay.jobId());
        assertEquals("WAIT_APPROVAL",str(workflow(workflowId),"state"));assertRisk(workflowId,35,0);assertEquals(0,events("RESERVE"));assertEquals(0,events("RELEASE"));assertEquals(0,count("mock_payment"));
    }
    @Test void grantExpiryAtSixtySecondsReleasesTheReservationEvenWithinLease() {
        UUID workflowId=ready102();var pay=approve(workflowId);payments.reserve(pay.jobId(),pay.token());
        clock.set(clock.now().plusSeconds(60));var answer=payments.commit(pay.jobId(),pay.token());
        assertEquals("WAIT_APPROVAL",answer.get("state"));assertEquals(0,count("mock_payment"));assertRisk(workflowId,35,0);assertEquals(1,events("RELEASE"));
    }
    @Test void revokedEvidenceAtFinalBoundaryStopsPaymentWithoutRefundingKycOrLoan() {
        UUID workflowId=ready102();var pay=approve(workflowId);payments.reserve(pay.jobId(),pay.token());
        tx.executeWithoutResult(status->{db.gate();db.update("update trusted_evidence set status='REVOKED',revoked_at=? where customer_id='customer-102' and evidence_type='FACE_MATCH'",clock.now());});
        var answer=payments.commit(pay.jobId(),pay.token());assertEquals("DENY",answer.get("decision"));assertEquals(0,count("mock_payment"));assertRisk(workflowId,35,0);assertEquals(1,events("RELEASE"));
    }
}
