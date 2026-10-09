package com.finsec.fuse.integration;

import com.finsec.fuse.common.ApiErrorHandler;
import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.payment.PaymentSupport;
import com.finsec.fuse.payment.PaymentTxService;
import com.finsec.fuse.persistence.ActionRequests;
import com.finsec.fuse.testing.PostgresSupport;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.SQLTransientConnectionException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.datasource.DelegatingDataSource;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Real PostgreSQL JDBC post-commit fault injection, NOT a network partition or process crash.
 * The test wrapper delegates Connection.commit() successfully, then loses its acknowledgement
 * by throwing once. The business service, transaction manager and exception advice are real.
 * Standalone MVC supplies only a test route; this does not test public routing/authentication.
 */
@Import(PaymentCommitAcknowledgementIT.FaultConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class PaymentCommitAcknowledgementIT extends PaymentFixture {
    private static final String WORKER = "fuse-worker";
    private static final String ACTION = "EXECUTE_MOCK_PAYMENT";
    private static final String LOST_ACK = "Test-only JDBC acknowledgement lost after successful PostgreSQL commit";
    @Autowired CommitFault fault;
    @Autowired ApiErrorHandler errorHandler;
    @Autowired ActionRequests actions;
    @Autowired PaymentSupport support;

    @AfterEach void disarm() { fault.target.remove(); }

    @Test
    void committedPaymentSurvivesLostJdbcAcknowledgementAndIdenticalReplayHasNoEffect() throws Exception {
        UUID workflowId = ready102();
        var lease = approve(workflowId);
        payments.reserve(lease.jobId(), lease.token());
        var job = db.required("SELECT * FROM workflow_job WHERE id=?", lease.jobId());
        UUID actionId = (UUID) job.get("execution_action_id");
        var body = support.actionBody(workflow(workflowId), job);
        String fingerprint = actions.fingerprint(WORKER, ACTION, workflowId, body);
        assertEquals(0, count("mock_payment"));
        assertEquals(0, events("CONSUME"));
        assertRisk(workflowId, 35, 50);
        assertInstanceOf(AcknowledgementDataSource.class, dataSource);

        var mvc = MockMvcBuilders.standaloneSetup(new CommitRoute(payments, lease.jobId(), lease.token()))
            .setControllerAdvice(errorHandler).build();
        // Arm only from the production final-commit gate, after reservation has really committed.
        hooks.onAfterCommitGate(() -> fault.arm(new Target(workflowId, lease.jobId(), actionId)));
        var failed = mvc.perform(post("/test-only/payment-commit")
            .header("Idempotency-Key", actionId.toString())).andReturn();
        hooks.reset();
        assertEquals(1, fault.successfulCommits.get(), "The delegate's commit must return before the injected exception");
        assertEquals(1, fault.injectedFailures.get());
        assertNull(fault.target.get(), "The fault must disarm before it can affect replay");
        assertNotNull(failed.getResolvedException(), "The real transaction failure must reach MVC advice");
        Throwable cause = failed.getResolvedException();
        while (cause.getCause() != null) cause = cause.getCause();
        var sqlFailure = assertInstanceOf(SQLTransientConnectionException.class, cause);
        assertEquals("08006", sqlFailure.getSQLState());
        assertEquals(LOST_ACK, sqlFailure.getMessage());
        assertEquals(503, failed.getResponse().getStatus());
        var uncertain = json.map(failed.getResponse().getContentAsString());
        assertEquals(actionId.toString(), uncertain.get("requestId"));
        assertEquals("ERROR", uncertain.get("decision"));
        assertTrue(uncertain.containsKey("state"));
        assertNull(uncertain.get("state"));
        assertEquals(List.of("DEPENDENCY_UNAVAILABLE"), uncertain.get("reasonCodes"));
        assertEquals("The operation outcome cannot be confirmed. After recovery, check using the same action ID and unchanged request",
            uncertain.get("message"), "Unknown commit outcomes must preserve safe, identical-action recovery guidance");
        assertFalse(failed.getResponse().getContentAsString().contains(LOST_ACK),
            "The public 503 response must not expose the injected JDBC exception text");
        assertEquals(false, uncertain.get("replayed"));
        assertFalse(uncertain.containsKey("paymentId"), "503 must not claim payment success or failure");

        // New physical connection, outside the pool/wrapper and Spring transaction manager.
        // Receipt and final states must already be visible before any application replay occurs.
        Map<String,Object> durableReceipt;
        try (var observer = DriverManager.getConnection(PostgresSupport.url(), "postgres", "");
             var query = observer.prepareStatement("""
                 SELECT p.receipt_json::text AS receipt, a.result_json::text AS action_receipt,
                        a.payload_hash, a.status AS action_status, j.state AS job_state,
                        w.state AS workflow_state, w.used_risk, w.reserved_risk,
                        (SELECT count(*) FROM mock_payment WHERE workflow_id=p.workflow_id) AS payment_count,
                        (SELECT count(*) FROM risk_ledger WHERE workflow_id=p.workflow_id
                            AND event_type='CONSUME') AS consume_count,
                        r.status AS reservation_status, ap.status AS approval_status,
                        g.status AS grant_status
                 FROM mock_payment p JOIN action_request a ON a.action_id=p.action_id
                 JOIN workflow_job j ON j.execution_action_id=p.action_id
                 JOIN workflow w ON w.id=p.workflow_id
                 JOIN payment_reservation r ON r.id=p.reservation_id
                 JOIN approval ap ON ap.id=p.approval_id
                 JOIN delegation_grant g ON g.id=r.grant_id
                 WHERE p.action_id=? AND p.workflow_id=? AND j.id=?
                 """)) {
            assertTrue(observer.getAutoCommit());
            query.setObject(1, actionId);
            query.setObject(2, workflowId);
            query.setObject(3, lease.jobId());
            try (var rows = query.executeQuery()) {
                assertTrue(rows.next(), "Independent connection must observe the committed payment");
                durableReceipt = json.map(rows.getString("receipt"));
                assertEquals(durableReceipt, json.map(rows.getString("action_receipt")));
                assertEquals(fingerprint, rows.getString("payload_hash"));
                assertEquals("SUCCEEDED", rows.getString("action_status"));
                assertEquals("SUCCEEDED", rows.getString("job_state"));
                assertEquals("PAID", rows.getString("workflow_state"));
                assertEquals("COMMITTED", rows.getString("reservation_status"));
                assertEquals("CONSUMED", rows.getString("approval_status"));
                assertEquals("CONSUMED", rows.getString("grant_status"));
                assertEquals(85, rows.getInt("used_risk"));
                assertEquals(0, rows.getInt("reserved_risk"));
                assertEquals(1, rows.getInt("payment_count"));
                assertEquals(1, rows.getInt("consume_count"));
                assertFalse(rows.next());
            }
        }
        assertEquals("PAID", durableReceipt.get("state"));
        assertEquals("ALLOW", durableReceipt.get("decision"));
        assertEquals(actionId.toString(), durableReceipt.get("requestId"));
        assertEquals(false, durableReceipt.get("replayed"));
        assertNotNull(durableReceipt.get("paymentId"));
        String beforeReplay = durableRows(workflowId);
        var expected = new LinkedHashMap<>(durableReceipt);
        expected.put("replayed", true);
        var replayed = mvc.perform(post("/test-only/payment-commit")
            .header("Idempotency-Key", actionId.toString())).andReturn();
        assertEquals(200, replayed.getResponse().getStatus());
        assertNull(replayed.getResolvedException());
        assertEquals(expected, json.map(replayed.getResponse().getContentAsString()));
        assertEquals(beforeReplay, durableRows(workflowId));
        // Historical success remains replayable even after execution authority expires.
        clock.set(clock.now().plusSeconds(3600));
        assertEquals(expected, paymentAgent.execute(lease.jobId(), lease.token()));
        assertEquals(beforeReplay, durableRows(workflowId));
        assertEquals(1, count("mock_payment"));
        assertEquals(1, events("RESERVE"));
        assertEquals(1, events("CONSUME"));
        assertEquals(0, events("RELEASE"));
        assertRisk(workflowId, 85, 0);
        assertEquals(1, fault.successfulCommits.get());
        assertEquals(1, fault.injectedFailures.get());
    }

    private String durableRows(UUID workflowId) {
        var rows = new LinkedHashMap<String,Object>();
        rows.put("workflow", workflow(workflowId));
        rows.put("stages", db.query("SELECT * FROM workflow_stage WHERE workflow_id=? ORDER BY stage", workflowId));
        for (String table : List.of("workflow_job", "agent_run", "agent_result", "approval",
                "payment_reservation", "mock_payment", "risk_ledger", "delegation_grant", "audit_event"))
            rows.put(table, db.query("SELECT * FROM " + table + " WHERE workflow_id=? ORDER BY id", workflowId));
        rows.put("actions", db.query("SELECT * FROM action_request WHERE workflow_id=? ORDER BY action_id", workflowId));
        rows.put("dependencies", db.query("SELECT * FROM run_dependency WHERE workflow_id=? ORDER BY parent_run_id,child_run_id", workflowId));
        return json.write(rows);
    }

    // Never component-scan this route into any application context; standalone MVC owns it.
    @Profile("commit-ack-standalone-route-only")
    @RestController
    static final class CommitRoute {
        private final PaymentTxService payments;
        private final UUID jobId;
        private final UUID token;
        CommitRoute(PaymentTxService payments, UUID jobId, UUID token) {
            this.payments = payments; this.jobId = jobId; this.token = token;
        }
        @PostMapping("/test-only/payment-commit")
        public Map<String,Object> commit() { return payments.commit(jobId, token); }
    }

    private record Target(UUID workflowId, UUID jobId, UUID actionId) {}

    static final class CommitFault {
        final ThreadLocal<Target> target = new ThreadLocal<>();
        final AtomicInteger successfulCommits = new AtomicInteger();
        final AtomicInteger injectedFailures = new AtomicInteger();
        void arm(Target value) {
            assertNull(target.get());
            assertEquals(0, injectedFailures.get());
            target.set(value);
        }
        void commit(Connection delegate) throws SQLException {
            Target current = target.get();
            if (current == null) { delegate.commit(); return; }
            // Verify this very transaction contains the targeted completed payment before committing.
            try (var query = delegate.prepareStatement("""
                    SELECT count(*) FROM mock_payment p
                    JOIN workflow_job j ON j.execution_action_id=p.action_id
                    JOIN action_request a ON a.action_id=p.action_id
                    WHERE p.action_id=? AND p.workflow_id=? AND j.id=?
                      AND j.state='SUCCEEDED' AND a.status='SUCCEEDED'
                    """)) {
                query.setObject(1, current.actionId());
                query.setObject(2, current.workflowId());
                query.setObject(3, current.jobId());
                try (var rows = query.executeQuery()) {
                    assertTrue(rows.next());
                    assertEquals(1, rows.getInt(1), "Fault may only target the completed payment transaction");
                }
            }
            delegate.commit();
            successfulCommits.incrementAndGet();
            target.remove();
            injectedFailures.incrementAndGet();
            throw new SQLTransientConnectionException(LOST_ACK, "08006");
        }
    }

    static final class AcknowledgementDataSource extends DelegatingDataSource {
        private final CommitFault fault;
        AcknowledgementDataSource(DataSource delegate, CommitFault fault) { super(delegate); this.fault = fault; }
        @Override public Connection getConnection() throws SQLException { return wrap(super.getConnection()); }
        @Override public Connection getConnection(String user, String password) throws SQLException {
            return wrap(super.getConnection(user, password));
        }
        private Connection wrap(Connection delegate) {
            return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(), new Class<?>[]{Connection.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("commit") && method.getParameterCount() == 0) {
                        fault.commit(delegate);
                        return null;
                    }
                    try { return method.invoke(delegate, args); }
                    catch (InvocationTargetException exception) { throw exception.getCause(); }
                });
        }
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class FaultConfiguration {
        @Bean static CommitFault commitFault() { return new CommitFault(); }
        @Bean static BeanPostProcessor acknowledgementWrapper(CommitFault fault) {
            return new BeanPostProcessor() {
                @Override public Object postProcessAfterInitialization(Object bean, String name) {
                    return bean instanceof DataSource source && !(bean instanceof AcknowledgementDataSource)
                        ? new AcknowledgementDataSource(source, fault) : bean;
                }
            };
        }
    }
}
