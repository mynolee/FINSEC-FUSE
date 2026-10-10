package com.finsec.fuse.payment;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;
import com.finsec.fuse.common.ApiException;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;

class PaymentIdempotencyIT extends PaymentFixture {
    @Test void twentyConcurrentCopiesProduceOnePaymentAndOneConsumption() throws Exception {
        UUID workflowId=ready102();var pay=approve(workflowId);
        var start=new CountDownLatch(1);var ready=new CountDownLatch(20);
        try(var pool=Executors.newFixedThreadPool(20)) {
            List<Future<Map<String,Object>>> results=new ArrayList<>();
            for(int i=0;i<20;i++)results.add(pool.submit(()->{ready.countDown();assertTrue(start.await(20,TimeUnit.SECONDS));return paymentAgent.execute(pay.jobId(),pay.token());}));
            assertTrue(ready.await(20,TimeUnit.SECONDS));start.countDown();
            Set<String> ids=new HashSet<>();for(var result:results)ids.add(result.get(30,TimeUnit.SECONDS).get("paymentId").toString());
            assertEquals(1,ids.size());
        }
        assertEquals(1,count("mock_payment"));assertEquals(1,events("RESERVE"));assertEquals(1,events("CONSUME"));
        assertRisk(workflowId,85,0);assertEquals("PAID",str(workflow(workflowId),"state"));
        assertEquals("SUCCEEDED",str(db.required("select * from workflow_job where id=?",pay.jobId()),"state"));
    }
    @Test void lostSuccessResponseIsHistoricalEvenAfterApprovalAndEvidenceExpiry() {
        UUID workflowId=ready102();var pay=approve(workflowId);var receipt=paymentAgent.execute(pay.jobId(),pay.token());
        clock.set(clock.now().plusSeconds(3600));
        var replay=paymentAgent.execute(pay.jobId(),pay.token());
        assertEquals(receipt.get("paymentId").toString(),replay.get("paymentId").toString());assertEquals(true,replay.get("replayed"));
        assertEquals(1,count("mock_payment"));assertEquals(1,events("CONSUME"));assertRisk(workflowId,85,0);
    }
    @Test void mismatchingFingerprintCannotReuseReservedExecution() {
        UUID workflowId=ready102();var pay=approve(workflowId);payments.reserve(pay.jobId(),pay.token());
        tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflowId);db.update("update payment_reservation set payload_hash=? where job_id=?","0".repeat(64),pay.jobId());});
        var ex=assertThrows(ApiException.class,()->payments.commit(pay.jobId(),pay.token()));assertEquals("REPLAY_CONFLICT",ex.reasonCode());
        assertEquals(0,count("mock_payment"));assertEquals(0,events("CONSUME"));assertRisk(workflowId,35,50);
    }
    @Test void reviewerCannotApproveAChangedSnapshot() {
        UUID workflowId=ready102();var preview=approvals.preview(REVIEWER,workflowId);
        tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflowId);db.update("update workflow set generation=generation+1 where id=?",workflowId);});
        var ex=assertThrows(ApiException.class,()->approvals.decide(REVIEWER,workflowId,UUID.randomUUID(),new ApprovalRequest(ApprovalRequest.Decision.APPROVE,(String)preview.get("reviewSnapshotHash"),"Stale preview")));
        assertEquals("REVIEW_CHANGED",ex.reasonCode());assertEquals(0,count("approval"));assertEquals(0,count("mock_payment"));
    }
    @Test void changedApprovalAmountCannotReachLedger() {
        UUID workflowId=ready102();var pay=approve(workflowId);payments.reserve(pay.jobId(),pay.token());
        tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflowId);db.update("update approval set amount_krw=2000000 where id=(select approval_id from workflow_job where id=?)",pay.jobId());});
        var response=payments.commit(pay.jobId(),pay.token());assertEquals("DENY",response.get("decision"));assertEquals("BLOCKED",response.get("state"));
        assertEquals(0,count("mock_payment"));assertEquals(1,events("RELEASE"));assertRisk(workflowId,35,0);
    }
}
