package com.finsec.fuse.integration;

import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.workflow.JobTransactions;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SC-T24-B13/B14/B17: real committed PostgreSQL rows, synthetic local KYC proposal,
 * no payment-ledger injection and no provider call. The injected TimeSource proves
 * application-time boundary behavior, not independent PostgreSQL clock calibration.
 * Spec: completion requires leaseUntil > now; JobTransactions.expired uses <=,
 * and PaymentTxService.reap returns only while now.isBefore(leaseUntil).
 */
class UncommittedPaymentLeaseBoundaryIT extends PaymentFixture {
    @ParameterizedTest(name="reservation={0}, lease age={1}s")
    @CsvSource({"true,89", "true,90", "true,91", "false,89", "false,90", "false,91"})
    void uncommittedLeaseRequiresFreshAuthorityWithoutInventingRelease(boolean reserved, int age) {
        UUID workflowId = ready102();
        // Create genuine, nonempty approval/job history without adding a prior reservation.
        var historical = approve(workflowId);
        clock.set(instant(job(historical.jobId()), "lease_until"));
        payments.reap(historical.jobId());
        assertEquals("REVOKED", approval(historical).get("status"));
        var lease = approve(workflowId);
        var originalJob = job(lease.jobId());
        UUID actionId = (UUID) originalJob.get("execution_action_id");
        Instant claimedAt = instant(originalJob, "started_at");
        Instant expiresAt = instant(originalJob, "lease_until");
        assertEquals(claimedAt.plusSeconds(90), expiresAt);
        if (reserved) assertEquals("PAYMENT_RESERVED", payments.reserve(lease.jobId(), lease.token()).get("state"));
        var reservation = db.one("SELECT * FROM payment_reservation WHERE job_id=?", lease.jobId()).orElse(null);
        assertEquals(reserved, reservation != null);
        assertRisk(workflowId, 35, reserved ? 50 : 0);
        assertEquals(0, count("mock_payment"));
        assertEquals(0, events("RELEASE"));
        assertEquals(reserved ? 1 : 0, events("RESERVE"));
        assertEquals(reserved ? "RESERVED" : "AVAILABLE", approval(lease).get("status"));
        String historyBefore = history(lease);
        String approvalTerms = without(approval(lease), "status");
        String grantTerms = reserved ? without(grant(reservation), "status") : null;
        String reservationTerms = reserved ? without(reservation, "status", "completed_at") : null;
        String jobTerms = without(job(lease.jobId()), "state", "last_error", "completed_at");
        String runTerms = reserved ? without(db.required("SELECT * FROM agent_run WHERE id=?", reservation.get("run_id")), "status", "completed_at") : null;

        clock.set(claimedAt.plusSeconds(age));
        // Claim this independent KYC at the test boundary, so it remains actively leased.
        UUID independent = start("customer-103");
        var current = jobs.claim().orElseThrow();
        assertEquals(independent, current.workflowId());
        assertEquals("KYC", current.phase());
        var prepared = kyc.prepare(current.jobId(), current.token()).orElseThrow();
        assertLive(current, prepared.input().runId());
        String independentBefore = durableWorkflow(independent);
        // Capture after independent setup because it legitimately issues its own KYC grant.
        String grantsBefore = json.write(db.query("SELECT * FROM delegation_grant ORDER BY id"));
        long grantCountBefore = count("delegation_grant");
        String dependenciesBefore = json.write(db.query("SELECT * FROM run_dependency ORDER BY parent_run_id,child_run_id"));
        String actionsBefore = json.write(db.query("SELECT * FROM action_request ORDER BY action_id"));
        assertEquals(age >= 90, jobs.expired().stream().anyMatch(row -> lease.jobId().equals(row.get("id"))));
        Map<String,String> before = committedRows();
        payments.reap(lease.jobId());
        if (age == 89) {
            assertEquals(before, committedRows(), "Before expiry, every committed row must be unchanged");
            payments.reap(lease.jobId());
            assertEquals(before, committedRows(), "Repeated pre-expiry reaping is also inert");
            // Finish this fixture through the exact boundary without ever executing its expired grant.
            clock.set(expiresAt);
            assertTrue(jobs.expired().stream().anyMatch(row -> lease.jobId().equals(row.get("id"))));
            payments.reap(lease.jobId());
        }
        assertEquals("WAIT_APPROVAL", workflow(workflowId).get("state"));
        assertRisk(workflowId, 35, 0);
        assertEquals("FAILED", job(lease.jobId()).get("state"));
        assertEquals(jobTerms, without(job(lease.jobId()), "state", "last_error", "completed_at"));
        assertEquals(grantCountBefore, count("delegation_grant"));
        assertEquals(reserved ? 1 : 0, count("payment_reservation"));
        assertEquals("APPROVAL_REQUIRED", job(lease.jobId()).get("last_error"));
        assertEquals(clock.now(), instant(job(lease.jobId()), "completed_at"));
        assertEquals("REVOKED", approval(lease).get("status"));
        assertEquals(approvalTerms, without(approval(lease), "status"));
        assertEquals(historyBefore, history(lease), "Historical approvals, results, grants, jobs and stage charges survive");
        assertEquals(dependenciesBefore, json.write(db.query("SELECT * FROM run_dependency ORDER BY parent_run_id,child_run_id")));
        assertEquals(actionsBefore, json.write(db.query("SELECT * FROM action_request ORDER BY action_id")));
        assertEquals(0, count("mock_payment"));
        assertEquals(0, events("CONSUME"));
        assertTrue(db.one("SELECT * FROM action_request WHERE action_id=?", actionId).isEmpty());
        assertTrue(jobs.expired().stream().noneMatch(row -> lease.jobId().equals(row.get("id"))));
        if (reserved) {
            var released = db.required("SELECT * FROM payment_reservation WHERE job_id=?", lease.jobId());
            assertEquals("RELEASED", released.get("status"));
            assertEquals(reservationTerms, without(released, "status", "completed_at"));
            assertEquals(clock.now(), instant(released, "completed_at"));
            assertEquals("EXPIRED", grant(reservation).get("status"));
            assertEquals(grantTerms, without(grant(reservation), "status"), "Never refresh or replace the expired grant");
            var releases = db.query("SELECT * FROM risk_ledger WHERE event_type='RELEASE'");
            assertEquals(1, releases.size());
            var release = releases.getFirst();
            assertEquals(50, ((Number) release.get("points")).intValue());
            assertEquals("PAYMENT", release.get("stage"));
            assertEquals(workflowId, release.get("workflow_id"));
            assertEquals(lease.generation(), ((Number) release.get("generation")).intValue());
            assertEquals(reservation.get("id"), release.get("reservation_id"));
            assertEquals(reservation.get("run_id"), release.get("run_id"));
            assertEquals(actionId, release.get("action_id"));
            assertEquals(clock.now(), instant(release, "created_at"));
            var failedRun = db.required("SELECT * FROM agent_run WHERE id=?", reservation.get("run_id"));
            assertEquals("FAILED", failedRun.get("status"));
            assertEquals(runTerms, without(failedRun, "status", "completed_at"));
        } else {
            assertEquals(grantsBefore, json.write(db.query("SELECT * FROM delegation_grant ORDER BY id")));
            assertEquals(0, count("payment_reservation"));
            assertEquals(0, events("RESERVE"));
            assertEquals(0, events("RELEASE"));
            assertNull(job(lease.jobId()).get("run_id"));
        }
        Map<String,String> reaped = committedRows();
        payments.reap(lease.jobId());
        clock.set(clock.now().plusSeconds(1));
        payments.reap(lease.jobId());
        assertEquals(reaped, committedRows(), "Repeated reaping cannot invent authority, release or receipt");
        assertStale(lease, () -> payments.reserve(lease.jobId(), lease.token()));
        assertStale(lease, () -> payments.commit(lease.jobId(), lease.token()));
        assertStale(lease, () -> paymentAgent.execute(lease.jobId(), lease.token()));
        assertEquals(independentBefore, durableWorkflow(independent));
        assertLive(current, prepared.input().runId());

        // Positive control: only a new explicit approval creates a new job/action/grant/reservation.
        var fresh = approve(workflowId);
        assertNotEquals(lease.jobId(), fresh.jobId());
        assertNotEquals(actionId, job(fresh.jobId()).get("execution_action_id"));
        assertNotEquals(job(lease.jobId()).get("approval_id"), job(fresh.jobId()).get("approval_id"));
        assertEquals("PAID", paymentAgent.execute(fresh.jobId(), fresh.token()).get("state"));
        var freshReservation = db.required("SELECT * FROM payment_reservation WHERE job_id=?", fresh.jobId());
        if (reserved) {
            assertNotEquals(reservation.get("id"), freshReservation.get("id"));
            assertNotEquals(reservation.get("grant_id"), freshReservation.get("grant_id"));
            assertEquals("EXPIRED", grant(reservation).get("status"));
        }
        assertRisk(workflowId, 85, 0);
        assertEquals(1, count("mock_payment"));
        assertEquals(reserved ? 1 : 0, events("RELEASE"));
        assertEquals(reserved ? 2 : 1, events("RESERVE"));
        assertEquals(1, events("CONSUME"));
        assertEquals(independentBefore, durableWorkflow(independent));
        assertLive(current, prepared.input().runId());
    }

    private void assertStale(JobTransactions.Lease lease, java.util.function.Supplier<Map<String,Object>> attempt) {
        Map<String,String> before = committedRows();
        var audits = db.query("SELECT * FROM audit_event ORDER BY id");
        var response = attempt.get();
        assertEquals("DENY", response.get("decision"));
        assertEquals(List.of("STALE_LEASE"), response.get("reasonCodes"));
        Map<String,String> after = committedRows();
        before.remove("audit_event"); after.remove("audit_event");
        assertEquals(before, after, "Stale execution may append a discard audit only");
        var afterAudits = db.query("SELECT * FROM audit_event ORDER BY id");
        assertEquals(audits.size()+1, afterAudits.size());
        for (var old : audits) assertTrue(afterAudits.stream().anyMatch(row -> json.write(row).equals(json.write(old))));
        var added = afterAudits.stream().filter(row -> audits.stream().noneMatch(old -> old.get("id").equals(row.get("id")))).findFirst().orElseThrow();
        assertEquals("LATE_RESULT_DISCARDED", added.get("event_type"));
        assertEquals("STALE_LEASE", added.get("reason_code"));
        assertEquals(lease.workflowId(), added.get("workflow_id"));
        assertEquals(job(lease.jobId()).get("execution_action_id"), added.get("action_id"));
    }

    /** Catalog-driven, complete committed row values, including bytea and all empty tables. */
    private Map<String,String> committedRows() {
        var rows = new LinkedHashMap<String,String>();
        for (var table : db.query("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")) {
            String name = table.get("tablename").toString();
            assertTrue(name.matches("[a-zA-Z_][a-zA-Z_0-9]*"));
            rows.put(name, db.required("SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text AS rows FROM public.\""+name+"\" t").get("rows").toString());
        }
        return rows;
    }

    private String history(JobTransactions.Lease lease) {
        UUID workflowId = lease.workflowId();
        UUID approvalId = (UUID) job(lease.jobId()).get("approval_id");
        UUID actionId = (UUID) job(lease.jobId()).get("execution_action_id");
        var rows = new LinkedHashMap<String,Object>();
        rows.put("approvals", db.query("SELECT * FROM approval WHERE workflow_id=? AND id<>? ORDER BY id", workflowId, approvalId));
        rows.put("jobs", db.query("SELECT * FROM workflow_job WHERE workflow_id=? AND id<>? ORDER BY id", workflowId, lease.jobId()));
        rows.put("runs", db.query("SELECT * FROM agent_run WHERE workflow_id=? AND role<>'PAYMENT' ORDER BY id", workflowId));
        rows.put("results", db.query("SELECT * FROM agent_result WHERE workflow_id=? ORDER BY id", workflowId));
        rows.put("grants", db.query("SELECT * FROM delegation_grant WHERE workflow_id=? AND action_id<>? ORDER BY id", workflowId, actionId));
        rows.put("stages", db.query("SELECT * FROM workflow_stage WHERE workflow_id=? AND stage<>'PAYMENT' ORDER BY stage", workflowId));
        for (String table : List.of("run_source_use", "run_evidence_use"))
            rows.put(table, db.query("SELECT to_jsonb(t)::text AS row FROM "+table+" t JOIN agent_run r ON r.id=t.run_id WHERE r.workflow_id=? ORDER BY to_jsonb(t)::text", workflowId));
        rows.put("charges", db.query("SELECT * FROM risk_ledger WHERE workflow_id=? AND event_type='CHARGE' ORDER BY id", workflowId));
        return json.write(rows);
    }

    private String durableWorkflow(UUID id) {
        var rows = new LinkedHashMap<String,Object>();
        rows.put("workflow", workflow(id));
        for (String table : List.of("workflow_stage", "workflow_job", "agent_run", "agent_result", "approval", "delegation_grant", "payment_reservation", "risk_ledger", "mock_payment", "audit_event", "action_request", "run_dependency"))
            rows.put(table, db.query("SELECT to_jsonb(t)::text AS row FROM "+table+" t WHERE workflow_id=? ORDER BY to_jsonb(t)::text", id));
        for (String table : List.of("run_source_use", "run_evidence_use"))
            rows.put(table, db.query("SELECT to_jsonb(t)::text AS row FROM "+table+" t JOIN agent_run r ON r.id=t.run_id WHERE r.workflow_id=? ORDER BY to_jsonb(t)::text", id));
        return json.write(rows);
    }

    private void assertLive(JobTransactions.Lease lease, UUID runId) {
        var current = job(lease.jobId());
        assertEquals("RUNNING", current.get("state"));
        assertEquals(lease.workflowId(), current.get("workflow_id"));
        assertEquals(lease.token(), current.get("lease_token"));
        assertEquals(lease.generation(), ((Number) current.get("generation")).intValue());
        assertEquals(runId, current.get("run_id"));
        assertEquals("RUNNING", db.required("SELECT * FROM agent_run WHERE id=?", runId).get("status"));
        assertTrue(clock.now().isBefore(instant(current, "lease_until")));
    }

    private Map<String,Object> job(UUID id) { return db.required("SELECT * FROM workflow_job WHERE id=?", id); }
    private Map<String,Object> approval(JobTransactions.Lease lease) { return db.required("SELECT * FROM approval WHERE id=?", job(lease.jobId()).get("approval_id")); }
    private Map<String,Object> grant(Map<String,Object> reservation) { return db.required("SELECT * FROM delegation_grant WHERE id=?", reservation.get("grant_id")); }
    private Instant instant(Map<String,Object> row, String key) { return ((Timestamp) row.get(key)).toInstant(); }
    private String without(Map<String,Object> row, String... columns) {
        var copy = new LinkedHashMap<>(row);
        for (String column : columns) copy.remove(column);
        return json.write(copy);
    }
}
