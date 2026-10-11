package com.finsec.fuse.observation;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;

import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.policy.QuarantineMatcher;
import com.finsec.fuse.workflow.KycContract;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class QuarantineObservationIT extends PaymentFixture {
    @Autowired QuarantineMatcher matcher;

    @Test void paymentAfterQuarantineMeasuresCommitToFirstRealDenialAndIgnoresReadsOrWrongToken() {
        UUID workflow = ready102();var pay = approve(workflow);
        assertEquals("PAYMENT_RESERVED", payments.reserve(pay.jobId(), pay.token()).get("state"));
        var clockNanos = new AtomicLong(10);var reads = new AtomicLong();
        var observation = QuarantineObservation.begin(() -> { reads.incrementAndGet();return clockNanos.get(); });
        UUID incident;
        try (observation) {
            incident = tx.execute(status -> {
                var response = quarantines.automaticRun(kycRun(workflow), "SECURITY_INVESTIGATION", "Commit-bound observation");
                assertEquals(0, reads.get(), "Service return inside an outer transaction is not commit");
                clockNanos.set(1_000);
                return (UUID) response.get("quarantineId");
            });
            assertEquals(1, reads.get());
            assertTrue(matcher.workflowQuarantined(workflow));quarantines.impact(SECURITY, incident);
            payments.commit(pay.jobId(), UUID.randomUUID());
            assertEquals(1, reads.get(), "Read-only matches and wrong-lease attempts are not a correlated denial");
            clockNanos.set(1_250);
            var denied = payments.commit(pay.jobId(), pay.token());
            assertEquals("BLOCKED", denied.get("state"));assertEquals("DENY", denied.get("decision"));
            clockNanos.set(5_000);payments.commit(pay.jobId(), pay.token());
        }
        var timing = observation.result();assertEquals(0.00025, timing.quarantineLatencyMs());
        assertEquals(incident, timing.incidents().getFirst().quarantineId());
        assertEquals(pay.jobId(), timing.incidents().getFirst().firstDenial().jobId());
        assertEquals(QuarantineObservation.Attempt.PAYMENT_EXECUTION, timing.incidents().getFirst().firstDenial().attempt());
        assertEquals(1, timing.observedDenialCount());assertEquals(0, count("mock_payment"));
        assertEquals(1, events("RELEASE"));assertEquals(0, events("CONSUME"));assertRisk(workflow, 35, 0);
    }

    @Test void lateKycResponseCorrelatesOnlyAfterCommittedRunQuarantine() {
        UUID workflow = start("customer-102");var prepared = prepareKyc();
        var clockNanos = new AtomicLong(50);var observation = QuarantineObservation.begin(clockNanos::get);
        try (observation) {
            quarantines.automaticRun(prepared.input().runId(), "SECURITY_INVESTIGATION", "Late KYC observation");
            clockNanos.set(125);kyc.apply(prepared, verified(prepared));
        }
        var denial = observation.result().incidents().getFirst().firstDenial();
        assertEquals(75, denial.elapsedNanos());assertEquals(prepared.input().runId(), denial.runId());
        assertEquals(QuarantineObservation.Attempt.KYC_RESULT_APPLY, denial.attempt());
        assertEquals("BLOCKED", str(workflow(workflow), "state"));assertEquals(0, count("agent_result"));
        assertEquals(0, count("mock_payment"));assertRisk(workflow, 10, 0);
        assertEquals(1, db.query("select id from audit_event where event_type='LATE_RESULT_DISCARDED'").size());
    }

    @Test void rolledBackQuarantineDoesNotProduceAnOriginOrPreventPayment() {
        UUID workflow = ready102();var pay = approve(workflow);payments.reserve(pay.jobId(), pay.token());
        var observation = QuarantineObservation.begin();
        try (observation) {
            tx.executeWithoutResult(status -> {
                quarantines.automaticRun(kycRun(workflow), "SECURITY_INVESTIGATION", "Rollback origin");
                status.setRollbackOnly();
            });
            assertEquals("PAID", payments.commit(pay.jobId(), pay.token()).get("state"));
        }
        assertTrue(observation.result().incidents().isEmpty());assertNull(observation.result().quarantineLatencyMs());
        assertEquals(0, count("quarantine"));assertEquals(1, count("mock_payment"));assertRisk(workflow, 85, 0);
    }

    @Test void rolledBackDenialIsIgnoredAndLaterCommittedAttemptSuppliesEndpoint() {
        UUID workflow = start("customer-102");var prepared = prepareKyc();
        var clockNanos = new AtomicLong(100);var observation = QuarantineObservation.begin(clockNanos::get);
        try (observation) {
            quarantines.automaticRun(prepared.input().runId(), "SECURITY_INVESTIGATION", "Rollback endpoint");
            clockNanos.set(150);
            tx.executeWithoutResult(status -> { kyc.apply(prepared, verified(prepared));status.setRollbackOnly(); });
            assertEquals(0, db.query("select id from audit_event where event_type='LATE_RESULT_DISCARDED'").size());
            clockNanos.set(500);kyc.apply(prepared, verified(prepared));
        }
        assertEquals(400, observation.result().incidents().getFirst().firstDenial().elapsedNanos());
        assertEquals("BLOCKED", str(workflow(workflow), "state"));assertEquals(0, count("mock_payment"));
    }

    @Test void unrelatedLateKycAndWrongLeaseAndExpiredLeaseAreNotQuarantineEndpoints() {
        start("customer-101");var quarantined = prepareKyc();
        start("customer-102");var unrelated = prepareKyc();
        var observation = QuarantineObservation.begin();
        try (observation) {
            quarantines.automaticRun(quarantined.input().runId(), "SECURITY_INVESTIGATION", "Ignore unrelated denials");
            kyc.apply(new KycContract.Prepared(unrelated.jobId(), UUID.randomUUID(), unrelated.input()), verified(unrelated));
            kyc.apply(new KycContract.Prepared(quarantined.jobId(), UUID.randomUUID(), quarantined.input()), verified(quarantined));
            clock.set(clock.now().plusSeconds(91));
            kyc.apply(quarantined, verified(quarantined));
        }
        assertEquals(1, observation.result().incidents().size());assertNull(observation.result().quarantineLatencyMs());
        assertNull(observation.result().incidents().getFirst().firstDenial());
        assertEquals(0, count("mock_payment"));
    }

    @Test void noExecutionAndReadOnlyImpactRemainUnmeasured() {
        UUID workflow = start("customer-102");var prepared = prepareKyc();var observation = QuarantineObservation.begin();
        try (observation) {
            var incident = quarantines.automaticRun(prepared.input().runId(), "SECURITY_INVESTIGATION", "Read-only observation");
            assertTrue(matcher.isQuarantined(prepared.input().runId()));assertTrue(matcher.workflowQuarantined(workflow));
            quarantines.impact(SECURITY, (UUID) incident.get("quarantineId"));
        }
        assertEquals(1, observation.result().incidents().getFirst().affectedExecutionCount());
        assertNull(observation.result().quarantineLatencyMs());
    }

    @Test void denialBeforeOriginCommitAndNextCaseCannotProduceLatency() {
        start("customer-102");var prepared = prepareKyc();var first = QuarantineObservation.begin();
        try (first) {
            tx.executeWithoutResult(status -> {
                quarantines.automaticRun(prepared.input().runId(), "SECURITY_INVESTIGATION", "Same transaction is not after commit");
                kyc.apply(prepared, verified(prepared));
            });
        }
        assertEquals(1, first.result().incidents().size());assertNull(first.result().quarantineLatencyMs());
        var next = QuarantineObservation.begin();
        try (next) { kyc.apply(prepared, verified(prepared)); }
        assertTrue(next.result().incidents().isEmpty());assertNull(next.result().quarantineLatencyMs());
    }

    @Test void alreadyPaidWorkflowHasNoDenialObservationOrInventedZero() {
        UUID workflow = ready102();var pay = approve(workflow);paymentAgent.execute(pay.jobId(), pay.token());
        var observation = QuarantineObservation.begin();
        try (observation) {
            quarantines.automaticRun(kycRun(workflow), "SECURITY_INVESTIGATION", "Past payment retained");
            assertEquals("PAID", payments.commit(pay.jobId(), pay.token()).get("state"));
        }
        assertEquals(1, observation.result().incidents().size());
        assertEquals(0, observation.result().incidents().getFirst().affectedExecutionCount());
        assertNull(observation.result().quarantineLatencyMs());assertEquals(1, count("mock_payment"));assertRisk(workflow, 85, 0);
    }
}
