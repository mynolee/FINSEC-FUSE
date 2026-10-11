package com.finsec.fuse.observation;

import static com.finsec.fuse.payment.PaymentValues.str;
import static org.junit.jupiter.api.Assertions.*;

import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.workflow.KycContract;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class KycQuarantineBindingIT extends PaymentFixture {
    @ParameterizedTest
    @ValueSource(strings = {"customer", "document", "evidence", "storedBytes"})
    void malformedInputCannotSupplyQuarantineTimingEndpoint(String corruption) {
        var workflow = start("customer-102");
        var original = prepareKyc();
        var input = original.input();
        var documents = input.documents();
        var facts = input.evidenceFacts();
        String customer = input.customerId();
        switch (corruption) {
            case "customer" -> customer = "customer-103";
            case "document" -> {
                var document = documents.getFirst();
                documents = List.of(new KycContract.Document(document.documentId(), document.documentVersion(),
                        document.contentHash(), document.text() + " altered synthetic content"));
            }
            case "evidence" -> {
                var fact = facts.getFirst();
                facts = List.of(new KycContract.EvidenceFact(fact.evidenceId(), fact.kind(), "FAIL"));
            }
            case "storedBytes" -> db.update("UPDATE agent_run SET input_bytes=? WHERE id=?",
                    "corrupted persisted synthetic input".getBytes(StandardCharsets.UTF_8), input.runId());
            default -> throw new AssertionError("Unknown fixture corruption");
        }
        var changed = new KycContract.Input(input.requestId(), input.workflowId(), input.generation(), input.runId(),
                customer, input.policyVersion(), input.inputSnapshotHash(), facts, documents);
        var malformed = new KycContract.Prepared(original.jobId(), original.leaseToken(), changed);
        var response = verified(malformed);
        assertTrue(response.boundTo(changed), "Copied identifiers and digest alone still bind the response");
        assertEquals(input.inputSnapshotHash(), changed.inputSnapshotHash());

        var nanos = new AtomicLong(100);
        var observation = QuarantineObservation.begin(nanos::get);
        try (observation) {
            quarantines.automaticRun(input.runId(), "SECURITY_INVESTIGATION", "Synthetic binding regression");
            nanos.set(250);
            kyc.apply(malformed, response);
        }
        assertEquals(1, observation.result().incidents().size());
        assertNull(observation.result().quarantineLatencyMs());
        assertNull(observation.result().incidents().getFirst().firstDenial());
        assertEquals(0, observation.result().observedDenialCount());
        assertEquals("BLOCKED", str(workflow(workflow), "state"));
        assertEquals(0, count("agent_result"));
        assertEquals(0, count("mock_payment"));
        assertEquals(1, db.query("SELECT id FROM audit_event WHERE event_type='LATE_RESULT_DISCARDED'").size());
    }

    @Test void intactInputSuppliesActualCommittedQuarantineDenialEndpoint() {
        start("customer-102");
        var prepared = prepareKyc();
        var nanos = new AtomicLong(100);
        var observation = QuarantineObservation.begin(nanos::get);
        try (observation) {
            quarantines.automaticRun(prepared.input().runId(), "SECURITY_INVESTIGATION", "Valid binding control");
            nanos.set(250);
            kyc.apply(prepared, verified(prepared));
        }
        var timing = observation.result();
        assertEquals(1, timing.observedDenialCount());
        assertEquals(0.00015, timing.quarantineLatencyMs());
        var denial = timing.incidents().getFirst().firstDenial();
        assertEquals(150, denial.elapsedNanos());
        assertEquals(prepared.input().runId(), denial.runId());
        assertEquals(QuarantineObservation.Attempt.KYC_RESULT_APPLY, denial.attempt());
        assertEquals(0, count("agent_result"));
        assertEquals(0, count("mock_payment"));
    }
}
