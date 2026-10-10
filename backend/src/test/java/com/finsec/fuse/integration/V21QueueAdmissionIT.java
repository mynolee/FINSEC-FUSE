package com.finsec.fuse.integration;

import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.payment.*;
import com.finsec.fuse.quarantine.ResumeRequest;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Real PG queue exhaustion must roll back complete approval/resume transactions. */
class V21QueueAdmissionIT extends PaymentFixture {
    private void fillPendingQueue() {
        tx.executeWithoutResult(status->{
            db.gate();
            for(int i=0;i<1000;i++) {
                String reference="QUEUE-ADMISSION-"+i;UUID app=UUID.randomUUID(),workflow=UUID.randomUUID();
                db.update("INSERT INTO application_registry(business_reference,customer_id,amount_krw,payout_account_id,document_id,document_version) SELECT ?,customer_id,amount_krw,payout_account_id,document_id,document_version FROM application_registry WHERE business_reference='APP-DEMO-102-001'",reference);
                db.update("INSERT INTO loan_application(id,business_reference,customer_id,amount_krw,payout_account_id) VALUES(?,?,'customer-102',1000000,?)",app,reference,UUID.fromString("00000000-0000-4000-8000-000000000102"));
                db.update("INSERT INTO workflow(id,application_id,root_authorization_id,risk_ledger_id,principal_id,policy_version,state) VALUES(?,?,?,?,?,'FUSE-MVP-2','KYC_PENDING')",workflow,app,UUID.randomUUID(),UUID.randomUUID(),"customer-102");
                db.update("INSERT INTO workflow_job(id,workflow_id,generation,phase,state,execution_action_id) VALUES(?,?,1,'KYC','PENDING',?)",UUID.randomUUID(),workflow,UUID.randomUUID());
            }
        });
        assertEquals(1000,pending());
    }
    private long pending(){return ((Number)db.required("SELECT count(*) n FROM workflow_job WHERE state='PENDING'").get("n")).longValue();}
    private void freeOneSlot(){tx.executeWithoutResult(s->{db.gate();db.update("UPDATE workflow_job SET state='FAILED' WHERE id=(SELECT id FROM workflow_job WHERE state='PENDING' ORDER BY id LIMIT 1)");});assertEquals(999,pending());}
    private String snapshot(UUID workflow) {
        var rows=new LinkedHashMap<String,Object>();rows.put("workflow",workflow(workflow));
        for(String table:List.of("approval","delegation_grant","agent_run","agent_result","workflow_job","risk_ledger","mock_payment","audit_event","action_request"))
            rows.put(table,db.query("SELECT * FROM "+table+" WHERE workflow_id=? ORDER BY "+(table.equals("action_request")?"action_id":"id"),workflow));
        return json.write(rows);
    }
    @Test void approvalAtFullQueueRollsBackApprovalStateAuditAndActionThenSameActionRetries() {
        UUID workflow=ready102(),action=UUID.randomUUID();
        var request=new ApprovalRequest(ApprovalRequest.Decision.APPROVE,(String)approvals.preview(REVIEWER,workflow).get("reviewSnapshotHash"),"Reviewed queue admission");
        fillPendingQueue();String before=snapshot(workflow);
        var error=assertThrows(ApiException.class,()->approvals.decide(REVIEWER,workflow,action,request));
        assertEquals(429,error.status());assertEquals("RATE_LIMITED",error.reasonCode());
        assertEquals(before,snapshot(workflow));assertEquals(1000,pending());assertEquals(0,count("approval"));assertEquals(0,count("mock_payment"));assertRisk(workflow,35,0);
        freeOneSlot();var accepted=approvals.decide(REVIEWER,workflow,action,request);
        assertEquals("APPROVED",accepted.get("state"));assertEquals(1000,pending());assertEquals(1,count("approval"));
        assertEquals(true,approvals.decide(REVIEWER,workflow,action,request).get("replayed"));assertEquals(1000,pending());assertEquals(1,count("approval"));
    }
    @Test void resumeAtFullQueueRollsBackGenerationStateHistoryAndActionThenSameActionRetries() {
        UUID workflow=start("customer-102"),action=UUID.randomUUID();var prepared=prepareKyc();
        clock.set(clock.now().plusSeconds(90));jobs.reapNonPayment(prepared.jobId());
        assertEquals("ON_HOLD",workflow(workflow).get("state"));
        var request=new ResumeRequest(1,"Dependency restored; explicit retry");
        fillPendingQueue();String before=snapshot(workflow);
        var error=assertThrows(ApiException.class,()->recovery.resume(REVIEWER,workflow,action,request));
        assertEquals(429,error.status());assertEquals("RATE_LIMITED",error.reasonCode());assertEquals(before,snapshot(workflow));assertEquals(1000,pending());assertRisk(workflow,10,0);
        freeOneSlot();var accepted=recovery.resume(REVIEWER,workflow,action,request);
        assertEquals("KYC_PENDING",accepted.get("state"));assertEquals(2,accepted.get("generation"));assertEquals(1000,pending());assertRisk(workflow,10,0);
        assertEquals(true,recovery.resume(REVIEWER,workflow,action,request).get("replayed"));assertEquals(1000,pending());assertEquals(2,((Number)workflow(workflow).get("generation")).intValue());
    }
}
