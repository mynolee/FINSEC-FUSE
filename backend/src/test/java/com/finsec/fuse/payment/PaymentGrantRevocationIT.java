package com.finsec.fuse.payment;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;

import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.policy.DelegationService;
import com.finsec.fuse.workflow.StartWorkflowRequest;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;

/** The final payment check must read the grant registry again after reservation commits. */
class PaymentGrantRevocationIT extends PaymentFixture {
    @Autowired DelegationService grants;
    @Autowired PaymentSupport support;

    @Test @Timeout(30)
    void revokingOnlyTheReservedGrantDeniesCommitAndPreservesAnIndependentApproval() {
        UUID workflowId=ready102();var pay=approve(workflowId);
        UUID otherWorkflow=ready103();var otherPay=approve(otherWorkflow);
        var independentBefore=workflowRows(otherWorkflow);

        assertEquals("PAYMENT_RESERVED",payments.reserve(pay.jobId(),pay.token()).get("state"));
        assertRisk(workflowId,35,50);
        var reservation=db.required("SELECT * FROM payment_reservation WHERE job_id=?",pay.jobId());
        UUID grantId=uuid(reservation,"grant_id"),approvalId=uuid(reservation,"approval_id");
        UUID actionId=uuid(reservation,"execution_action_id"),runId=uuid(reservation,"run_id");
        var grant=db.required("SELECT * FROM delegation_grant WHERE id=?",grantId);
        var approvalBefore=db.required("SELECT * FROM approval WHERE id=?",approvalId);
        assertEquals("ISSUED",str(grant,"status"));
        assertEquals("RESERVED",str(approvalBefore,"status"));
        assertEquals("RUNNING",str(db.required("SELECT * FROM agent_run WHERE id=?",runId),"status"));
        assertTrue(clock.now().isBefore(instant(grant,"expires_at")));
        assertTrue(clock.now().isBefore(instant(approvalBefore,"expires_at")));
        String signedTransport=json.write(grants.transport(grantId));
        tx.executeWithoutResult(status->{
            db.gate();db.lockWorkflow(workflowId);
            assertNull(support.currentFailure(workflow(workflowId),clock.now()));
            assertTrue(support.exactApproval(workflow(workflowId),approvalBefore,actionId,clock.now(),true));
            assertEquals(grantId,grants.validate(grants.transport(grantId),"LOAN",workflowId,runId,
                "EXECUTE_MOCK_PAYMENT",clock.now()).grantId());
        });

        var unchangedAuthority=rowsExceptRevokedGrantStatus(grantId);
        var sameTime=clock.now();
        tx.executeWithoutResult(status->{
            db.gate();db.lockWorkflow(workflowId);
            // REVOKED is the existing delegation_grant.status value, not an approval edit or quarantine.
            assertEquals(1,db.update("UPDATE delegation_grant SET status='REVOKED' WHERE id=? AND status='ISSUED'",grantId));
        });
        assertEquals(unchangedAuthority,rowsExceptRevokedGrantStatus(grantId),"Only the selected grant status may change before commit");
        assertEquals(signedTransport,json.write(grants.transport(grantId)));
        assertEquals(approvalBefore,db.required("SELECT * FROM approval WHERE id=?",approvalId));
        assertEquals(sameTime,clock.now());
        assertEquals(0,count("quarantine"));
        assertEquals(0,count("mock_payment"));
        tx.executeWithoutResult(status->{
            db.gate();db.lockWorkflow(workflowId);
            assertNull(support.currentFailure(workflow(workflowId),clock.now()));
            assertTrue(support.exactApproval(workflow(workflowId),approvalBefore,actionId,clock.now(),true));
        });

        var denied=payments.commit(pay.jobId(),pay.token());
        assertEquals("BLOCKED",denied.get("state"));
        assertEquals("DENY",denied.get("decision"));
        assertEquals(List.of("SCOPE_EXCEEDED"),denied.get("reasonCodes"));
        assertEquals("BLOCKED",str(workflow(workflowId),"state"));
        assertEquals("DENY",str(workflow(workflowId),"last_decision"));
        assertEquals("SCOPE_EXCEEDED",str(workflow(workflowId),"last_reason_code"));
        assertRisk(workflowId,35,0);
        assertEquals(0,count("mock_payment"));
        assertEquals(0,events("CONSUME"));
        assertEquals(1,events("RESERVE"));
        assertEquals(1,events("RELEASE"));
        assertEquals("RELEASED",str(db.required("SELECT * FROM payment_reservation WHERE id=?",uuid(reservation,"id")),"status"));
        var release=db.required("SELECT * FROM risk_ledger WHERE reservation_id=? AND event_type='RELEASE'",uuid(reservation,"id"));
        assertEquals(50,integer(release,"points"));
        assertEquals(actionId,uuid(release,"action_id"));
        assertEquals(runId,uuid(release,"run_id"));
        var stage=db.required("SELECT * FROM workflow_stage WHERE workflow_id=? AND stage='PAYMENT'",workflowId);
        assertEquals(0,integer(stage,"used_points"));
        assertEquals(0,integer(stage,"reserved_points"));
        assertEquals("REVOKED",str(db.required("SELECT * FROM delegation_grant WHERE id=?",grantId),"status"));
        assertNull(db.required("SELECT * FROM delegation_grant WHERE id=?",grantId).get("consumed_at"));
        assertEquals(signedTransport,json.write(grants.transport(grantId)));
        // Approval revocation happens only now, as fail-closed quarantine cleanup, not as the injected fault.
        assertEquals("REVOKED",str(db.required("SELECT * FROM approval WHERE id=?",approvalId),"status"));
        assertEquals("FAILED",str(db.required("SELECT * FROM workflow_job WHERE id=?",pay.jobId()),"state"));
        assertEquals("BLOCKED",str(db.required("SELECT * FROM agent_run WHERE id=?",runId),"status"));
        assertEquals(1,count("quarantine"));
        var quarantine=db.required("SELECT * FROM quarantine WHERE run_id=?",runId);
        assertEquals("RUN",str(quarantine,"scope"));
        assertEquals("ACTIVE",str(quarantine,"status"));
        assertEquals("SCOPE_EXCEEDED",str(quarantine,"reason_code"));
        assertEquals(1,db.query("SELECT id FROM audit_event WHERE workflow_id=? "
            +"AND event_type='QUARANTINE_APPLIED' AND reason_code='SCOPE_EXCEEDED'",workflowId).size());
        assertTrue(db.query("SELECT id FROM audit_event WHERE workflow_id=? AND event_type='PAYMENT_COMMITTED'",workflowId).isEmpty());
        assertEquals(independentBefore,workflowRows(otherWorkflow));

        // The scoped denial must not strand another customer's valid approval or payment.
        assertEquals("PAID",paymentAgent.execute(otherPay.jobId(),otherPay.token()).get("state"));
        assertRisk(otherWorkflow,85,0);
        assertRisk(workflowId,35,0);
        assertEquals(1,count("mock_payment"));
        assertEquals(otherWorkflow,uuid(db.required("SELECT * FROM mock_payment"),"workflow_id"));
        assertEquals(1,events("CONSUME"));
        assertEquals(1,events("RELEASE"));
        assertEquals(1,count("quarantine"));
    }

    private UUID ready103() {
        tx.executeWithoutResult(status->{db.gate();
            db.update("UPDATE application_registry SET amount_krw=500000 WHERE business_reference='APP-DEMO-103-001'");
        });
        var started=workflows.start(new Actor("customer-103","CUSTOMER",Set.of("customer-103")),UUID.randomUUID(),
            new StartWorkflowRequest("APP-DEMO-103-001","customer-103",500000L,
                UUID.fromString("00000000-0000-4000-8000-000000000103")));
        UUID workflowId=(UUID)started.get("workflowId");
        var prepared=prepareKyc();assertEquals(workflowId,prepared.input().workflowId());
        kyc.apply(prepared,verified(prepared));
        var loan=jobs.claim().orElseThrow();assertEquals("LOAN",loan.phase());
        loans.execute(loan.jobId(),loan.token());
        assertEquals("WAIT_APPROVAL",str(workflow(workflowId),"state"));
        return workflowId;
    }

    private Map<String,List<String>> rowsExceptRevokedGrantStatus(UUID grantId) {
        var rows=new LinkedHashMap<String,List<String>>();
        for(String table:List.of("execution_gate","loan_application","workflow","workflow_stage","workflow_job",
            "agent_run","agent_result","run_source_use","run_evidence_use","run_dependency","trusted_evidence",
            "action_request","approval","delegation_grant","payment_reservation","risk_ledger",
            "mock_payment","quarantine","quarantine_workflow_hold","audit_event")) {
            var contents=table.equals("delegation_grant")
                ?db.query("SELECT (CASE WHEN id=? THEN to_jsonb(r)-'status' ELSE to_jsonb(r) END)::text "
                    +"AS row_json FROM delegation_grant r ORDER BY row_json",grantId)
                :db.query("SELECT to_jsonb(r)::text AS row_json FROM "+table+" r ORDER BY row_json");
            rows.put(table,contents.stream().map(value->str(value,"row_json")).toList());
        }
        return rows;
    }

    private Map<String,List<String>> workflowRows(UUID workflowId) {
        var rows=new LinkedHashMap<String,List<String>>();
        for(String table:List.of("workflow","workflow_stage","workflow_job","agent_run","agent_result",
            "run_dependency","action_request","approval","delegation_grant","payment_reservation",
            "risk_ledger","mock_payment","quarantine_workflow_hold","audit_event")) {
            String key=table.equals("workflow")?"id":"workflow_id";
            rows.put(table,db.query("SELECT to_jsonb(r)::text AS row_json FROM "+table+" r WHERE "+key+"=? ORDER BY row_json",workflowId)
                .stream().map(value->str(value,"row_json")).toList());
        }
        return rows;
    }
}
