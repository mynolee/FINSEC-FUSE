package com.finsec.fuse.integration;

import static org.junit.jupiter.api.Assertions.*;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.payment.ApprovalRequest;
import com.finsec.fuse.payment.ApprovalService;
import com.finsec.fuse.payment.PaymentAgentService;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.testing.PostgresSupport;
import com.finsec.fuse.workflow.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.jdbc.datasource.init.ScriptUtils;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** Exercises the actual bootstrap grants and migrations with an unprivileged application connection. */
@SpringBootTest(classes=FuseApplication.class, webEnvironment=SpringBootTest.WebEnvironment.MOCK)
@ActiveProfiles("test")
@DirtiesContext(classMode=DirtiesContext.ClassMode.AFTER_CLASS)
class RuntimeDatabaseRoleIT {
    // All roles, passwords and databases belong only to PostgresSupport's disposable local process.
    // This class deliberately does not inherit FuseIntegrationTest's superuser schema-reset harness.
    private static final String TEST_PASSWORD="ephemeral-role-test-only";
    private static final Database DATABASE=provision();
    private static final Actor CUSTOMER=new Actor("customer-102","CUSTOMER",Set.of("customer-102"));
    private static final Actor REVIEWER=new Actor("staff-01","LOAN_REVIEWER",Set.of("customer-102"));

    @Autowired DataSource dataSource;
    @Autowired Db db;
    @Autowired WorkflowService workflows;
    @Autowired JobTransactions jobs;
    @Autowired KycTransactions kyc;
    @Autowired LoanTransactions loans;
    @Autowired ApprovalService approvals;
    @Autowired PaymentAgentService payments;

    private record Database(String url,String owner,String runtime,String experimentUrl,String experimentOwner) {}

    @DynamicPropertySource static void runtimeDatabase(DynamicPropertyRegistry registry) {
        PostgresSupport.properties(registry);
        registry.add("spring.datasource.url",DATABASE::url);
        registry.add("spring.datasource.username",DATABASE::runtime);
        registry.add("spring.datasource.password",()->TEST_PASSWORD);
        registry.add("spring.flyway.user",DATABASE::owner);
        registry.add("spring.flyway.password",()->TEST_PASSWORD);
    }

    private static Database provision() {
        String suffix=UUID.randomUUID().toString().replace("-","");
        String owner="it_owner_"+suffix, runtime="it_runtime_"+suffix;
        String database="it_fuse_"+suffix, experiment="it_exp_"+suffix, experimentOwner="it_exp_owner_"+suffix;
        // Strip EmbeddedPostgres's user query parameter so it cannot override the tested login role.
        String adminUrl=PostgresSupport.url().split("\\?",2)[0];
        String prefix=adminUrl.substring(0,adminUrl.lastIndexOf('/')+1);
        String url=prefix+database;
        try {
            try(var connection=DriverManager.getConnection(adminUrl,"postgres","");var statement=connection.createStatement()) {
                statement.execute("CREATE ROLE "+owner+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+TEST_PASSWORD+"'");
                statement.execute("CREATE DATABASE "+database+" OWNER "+owner);
            }
            Path script=Path.of("scripts/init-postgres.sh");
            if(!Files.isRegularFile(script))script=Path.of("../scripts/init-postgres.sh");
            String shell=Files.readString(script);
            String marker="<<'SQL'\n";
            int start=shell.indexOf(marker),end=shell.lastIndexOf("\nSQL");
            if(start<0 || end<start)throw new IllegalStateException("Cannot locate bootstrap SQL heredoc");
            String sql=shell.substring(start+marker.length(),end)
                .replace("fuse_experiment_owner",experimentOwner).replace("fuse_experiments",experiment)
                .replace("fuse_runtime",runtime).replace("fuse_owner",owner)
                .replaceAll("\\bfuse\\b",database)
                .replace(":'runtime_password'","'"+TEST_PASSWORD+"'")
                .replace(":'experiment_password'","'"+TEST_PASSWORD+"'");
            // The bootstrap administrator performs role/database creation; Flyway later logs in as owner.
            try(var connection=DriverManager.getConnection(url,"postgres","")) {
                ScriptUtils.executeSqlScript(connection,new ByteArrayResource(sql.getBytes(StandardCharsets.UTF_8)));
            }
            return new Database(url,owner,runtime,prefix+experiment,experimentOwner);
        } catch(Exception error) {throw new ExceptionInInitializerError(error);}
        // The shared embedded PostgreSQL shutdown hook removes these isolated databases and roles.
    }

    @Test void runtimeIsSeparateFromMigrationOwnerAndCannotDdlOrBypassHistoryTriggers() throws Exception {
        try(var connection=dataSource.getConnection()) {
            assertEquals(DATABASE.runtime(),value(connection,"SELECT current_user"));
            assertEquals(DATABASE.runtime(),value(connection,"SELECT session_user"));
            assertTrue(value(connection,"SHOW server_version").startsWith("16.15"));
            assertEquals("false",value(connection,"SELECT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)::text FROM pg_roles WHERE rolname=current_user"));
            assertEquals("false",value(connection,"SELECT has_schema_privilege(current_user,'public','CREATE')::text"));
            assertEquals("false",value(connection,"SELECT pg_has_role(current_user,'"+DATABASE.owner()+"','MEMBER')::text"));
            assertEquals("0",value(connection,"SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','S') AND pg_get_userbyid(c.relowner)<>'"+DATABASE.owner()+"'"));
            assertEquals("0",value(connection,"SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND pg_get_userbyid(p.proowner)<>'"+DATABASE.owner()+"'"));
        }
        for(String sql:new String[]{
            "CREATE TABLE public.runtime_must_not_create(id integer)",
            "CREATE SCHEMA runtime_must_not_create",
            "ALTER TABLE audit_event ADD COLUMN runtime_must_not_create integer",
            "ALTER TABLE audit_event DISABLE TRIGGER USER",
            "DROP TABLE audit_event",
            "DROP FUNCTION reject_immutable_mutation() CASCADE",
            "CREATE OR REPLACE FUNCTION reject_immutable_mutation() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END;'",
            "SET session_replication_role = replica",
            "SET ROLE "+DATABASE.owner(),
            "SET ROLE "+DATABASE.experimentOwner()
        }) assertDenied(sql,"42501");
        for(String table:new String[]{"audit_event","risk_ledger","source_document_version","loan_application","mock_payment","agent_result","quarantine_workflow_hold"})
            assertDenied("TRUNCATE TABLE "+table+" CASCADE","42501");
    }

    @Test void runtimeHasNormalDmlAndFutureOwnerSequencePrivileges() throws Exception {
        String customer="runtime-role-probe";
        assertEquals(1,db.update("INSERT INTO mock_profile(customer_id,monthly_income_krw,max_loan_amount_krw,profile_hash) VALUES(?,100,200,?)",customer,"a".repeat(64)));
        assertEquals(1,db.update("UPDATE mock_profile SET monthly_income_krw=300 WHERE customer_id=?",customer));
        assertEquals(300L,db.number(db.required("SELECT monthly_income_krw FROM mock_profile WHERE customer_id=?",customer),"monthly_income_krw"));
        assertEquals(1,db.update("DELETE FROM mock_profile WHERE customer_id=?",customer));

        // The present schema uses UUIDs. This owner-created probe checks default grants for future sequences.
        try(var connection=DriverManager.getConnection(DATABASE.url(),DATABASE.owner(),TEST_PASSWORD);var statement=connection.createStatement()) {
            statement.execute("CREATE TABLE runtime_sequence_probe(id bigserial PRIMARY KEY, value text NOT NULL)");
        }
        try(var connection=dataSource.getConnection();var statement=connection.createStatement()) {
            assertEquals("1",value(connection,"INSERT INTO runtime_sequence_probe(value) VALUES('mock') RETURNING id"));
            assertEquals("1",value(connection,"SELECT currval('runtime_sequence_probe_id_seq')"));
            assertEquals("1",value(connection,"SELECT last_value FROM runtime_sequence_probe_id_seq"));
            assertEquals(1,statement.executeUpdate("UPDATE runtime_sequence_probe SET value='updated' WHERE id=1"));
            assertEquals(1,statement.executeUpdate("DELETE FROM runtime_sequence_probe WHERE id=1"));
        }
        assertDenied("SELECT setval('runtime_sequence_probe_id_seq',99)","42501");
        assertDenied("ALTER SEQUENCE runtime_sequence_probe_id_seq RESTART WITH 99","42501");
        assertDenied("TRUNCATE runtime_sequence_probe","42501");
    }

    @Test void runtimeCompletesMockPaymentButCannotRewriteAppendOnlyHistory() throws Exception {
        UUID workflow=(UUID)workflows.start(CUSTOMER,UUID.randomUUID(),new StartWorkflowRequest(
            "APP-DEMO-102-001","customer-102",1_000_000L,UUID.fromString("00000000-0000-4000-8000-000000000102"))).get("workflowId");
        var kycLease=jobs.claim().orElseThrow();assertEquals("KYC",kycLease.phase());
        var prepared=kyc.prepare(kycLease.jobId(),kycLease.token()).orElseThrow();
        var input=prepared.input();
        kyc.apply(prepared,new KycContract.Response(input.requestId(),input.workflowId(),input.generation(),input.runId(),input.inputSnapshotHash(),
            new KycContract.Proposal(KycContract.ProposalStatus.VERIFIED,input.evidenceFacts().stream().map(KycContract.EvidenceFact::evidenceId).toList(),"Local replay fixture"),
            new KycContract.ModelMetadata("replay","KYC-PROMPT-1")));
        var loanLease=jobs.claim().orElseThrow();assertEquals("LOAN",loanLease.phase());
        loans.execute(loanLease.jobId(),loanLease.token());
        var preview=approvals.preview(REVIEWER,workflow);
        approvals.decide(REVIEWER,workflow,UUID.randomUUID(),new ApprovalRequest(ApprovalRequest.Decision.APPROVE,(String)preview.get("reviewSnapshotHash"),"Mock review confirmed"));
        var payLease=jobs.claim().orElseThrow();assertEquals("PAY",payLease.phase());
        assertEquals("PAID",payments.execute(payLease.jobId(),payLease.token()).get("state"));
        assertEquals(1L,count("mock_payment"));
        assertEquals(85L,db.number(db.required("SELECT sum(points) n FROM risk_ledger WHERE event_type IN ('CHARGE','CONSUME')"),"n"));

        UUID quarantine=UUID.randomUUID();
        db.update("INSERT INTO quarantine(id,scope,workflow_id,status,reason_code,actor_id,gate_epoch) VALUES(?,'WORKFLOW',?,'ACTIVE','TEST_ROLE_PROBE','security-01',0)",quarantine,workflow);
        db.update("INSERT INTO quarantine_workflow_hold(quarantine_id,workflow_id,generation) VALUES(?,?,1)",quarantine,workflow);
        for(String table:new String[]{"audit_event","risk_ledger","source_document_version","loan_application","mock_payment","quarantine_workflow_hold"}) {
            long before=count(table);assertTrue(before>0,"A real row must exercise the trigger for "+table);
            assertDenied("UPDATE "+table+" SET created_at=created_at+interval '1 second'","55000");
            assertDenied("DELETE FROM "+table,"55000");
            assertEquals(before,count(table),"History must remain intact for "+table);
        }
        assertDenied("UPDATE agent_result SET body_json='{}'::jsonb","55000");
        assertDenied("UPDATE agent_result SET result_hash='"+"b".repeat(64)+"'","55000");
        assertDenied("DELETE FROM agent_result","55000");
        assertEquals("PAID",db.required("SELECT state FROM workflow WHERE id=?",workflow).get("state"));
        assertEquals(1L,count("mock_payment"));
    }

    @Test void runtimeAndExperimentRolesCannotConnectToEachOthersDatabase() {
        SQLException runtime=assertThrows(SQLException.class,()->{
            try(var ignored=DriverManager.getConnection(DATABASE.experimentUrl(),DATABASE.runtime(),TEST_PASSWORD)) {fail("Runtime connected to the experiment database");}
        });
        assertEquals("42501",runtime.getSQLState());
        SQLException experiment=assertThrows(SQLException.class,()->{
            try(var ignored=DriverManager.getConnection(DATABASE.url(),DATABASE.experimentOwner(),TEST_PASSWORD)) {fail("Experiment owner connected to the workflow database");}
        });
        assertEquals("42501",experiment.getSQLState());
    }

    private long count(String table) {return db.number(db.required("SELECT count(*) n FROM "+table),"n");}
    private void assertDenied(String sql,String expectedState) {
        SQLException error=assertThrows(SQLException.class,()->{
            try(var connection=dataSource.getConnection();var statement=connection.createStatement()) {statement.execute(sql);}
        },sql);
        assertEquals(expectedState,error.getSQLState(),sql+": "+error.getMessage());
    }
    private static String value(Connection connection,String sql) throws SQLException {
        try(var statement=connection.createStatement();var result=statement.executeQuery(sql)) {
            assertTrue(result.next(),sql);return result.getString(1);
        }
    }
}
