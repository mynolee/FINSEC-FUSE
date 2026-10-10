package com.finsec.fuse.payment;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;

class QuarantinePaymentRaceIT extends PaymentFixture {
    @Test void quarantineCommittedAfterReservationPreventsPaymentAndReleasesOnlyReservedRisk() throws Exception {
        UUID workflowId=ready102();var pay=approve(workflowId);
        var reserved=new CountDownLatch(1);var continuePayment=new CountDownLatch(1);
        hooks.onAfterReservation(()->{reserved.countDown();await(continuePayment);});
        try(var pool=Executors.newSingleThreadExecutor()) {
            var payment=pool.submit(()->paymentAgent.execute(pay.jobId(),pay.token()));
            assertTrue(reserved.await(15,TimeUnit.SECONDS));assertRisk(workflowId,35,50);
            quarantines.automaticRun(kycRun(workflowId),"SECURITY_INVESTIGATION","Deterministic quarantine-first test");
            continuePayment.countDown();assertEquals("BLOCKED",payment.get(20,TimeUnit.SECONDS).get("state"));
        } finally {continuePayment.countDown();}
        assertEquals(0,count("mock_payment"));assertEquals(1,events("RELEASE"));assertEquals(0,events("CONSUME"));assertRisk(workflowId,35,0);
    }
    @Test void paymentThatHoldsGateFirstRemainsPaidAndIsReportedAsPastExposure() throws Exception {
        UUID workflowId=ready102();var pay=approve(workflowId);
        var paymentOwnsGate=new CountDownLatch(1);var finishPayment=new CountDownLatch(1);var quarantineStarted=new CountDownLatch(1);
        hooks.onAfterCommitGate(()->{paymentOwnsGate.countDown();await(finishPayment);});
        Map<String,Object> incident;
        try(var pool=Executors.newFixedThreadPool(2)) {
            var payment=pool.submit(()->paymentAgent.execute(pay.jobId(),pay.token()));
            assertTrue(paymentOwnsGate.await(15,TimeUnit.SECONDS));
            var quarantine=pool.submit(()->{quarantineStarted.countDown();return quarantines.automaticRun(kycRun(workflowId),"SECURITY_INVESTIGATION","Deterministic payment-first test");});
            assertTrue(quarantineStarted.await(15,TimeUnit.SECONDS));finishPayment.countDown();
            assertEquals("PAID",payment.get(20,TimeUnit.SECONDS).get("state"));incident=quarantine.get(20,TimeUnit.SECONDS);
        } finally {finishPayment.countDown();}
        assertEquals("PAID",str(workflow(workflowId),"state"));assertEquals(1,count("mock_payment"));assertRisk(workflowId,85,0);assertEquals(0,events("RELEASE"));
        var impact=quarantines.impact(SECURITY,(UUID)incident.get("quarantineId"));
        var actual=(Map<?,?>)impact.get("actual");assertEquals(1,((Number)actual.get("paymentCount")).intValue());assertEquals(1000000L,((Number)actual.get("paidAmountKrw")).longValue());
        assertEquals(1,((List<?>)impact.get("paidBeforeQuarantine")).size());
    }
    private static void await(CountDownLatch latch) {
        try{assertTrue(latch.await(20,TimeUnit.SECONDS));}catch(InterruptedException e){Thread.currentThread().interrupt();throw new AssertionError(e);}
    }
}
