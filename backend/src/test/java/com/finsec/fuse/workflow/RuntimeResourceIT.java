package com.finsec.fuse.workflow;

import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.testing.FuseIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Uses the real ephemeral PostgreSQL and the normal 2s/5s connection settings. */
class RuntimeResourceIT extends FuseIntegrationTest {
    @Autowired WorkflowService workflows;
    @Test void actualStatementAndLockTimeoutsReleaseResources() throws Exception {
        assertEquals("2s",db.required("SHOW lock_timeout").get("lock_timeout"));
        assertEquals("5s",db.required("SHOW statement_timeout").get("statement_timeout"));
        try(var blocker=dataSource.getConnection()) {
            blocker.setAutoCommit(false);
            blocker.createStatement().execute("SELECT id FROM execution_gate WHERE id=1 FOR UPDATE");
            var failure=assertThrows(DataAccessException.class,()->tx.executeWithoutResult(s->db.gate()));
            assertTrue(sqlState(failure,"55P03"));
            blocker.rollback();
        }
        tx.executeWithoutResult(s->db.gate());
        var timeout=assertThrows(DataAccessException.class,()->db.query("SELECT pg_sleep(6)"));
        assertTrue(sqlState(timeout,"57014"));
        assertEquals(1,((Number)db.required("SELECT 1 AS ready").get("ready")).intValue());
    }
    @Test void fullQueueRejectsAdmissionAndRollsBackWholeWorkflow() {
        tx.executeWithoutResult(s->{
            db.gate();
            for(int i=0;i<1000;i++) {
                UUID app=UUID.randomUUID(),workflow=UUID.randomUUID();
                db.update("INSERT INTO application_registry(business_reference,customer_id,amount_krw,payout_account_id,document_id,document_version) SELECT ?,customer_id,amount_krw,payout_account_id,document_id,document_version FROM application_registry WHERE business_reference='APP-DEMO-102-001'","QUEUE-FIXTURE-"+i);
                db.update("INSERT INTO loan_application(id,business_reference,customer_id,amount_krw,payout_account_id) VALUES(?,?,?,1000000,?)",app,"QUEUE-FIXTURE-"+i,"customer-102",UUID.fromString("00000000-0000-4000-8000-000000000102"));
                db.update("INSERT INTO workflow(id,application_id,root_authorization_id,risk_ledger_id,principal_id,policy_version,state) VALUES(?,?,?,?,?,'FUSE-MVP-2','KYC_PENDING')",workflow,app,UUID.randomUUID(),UUID.randomUUID(),"customer-102");
                db.update("INSERT INTO workflow_job(id,workflow_id,generation,phase,state,execution_action_id) VALUES(?,?,1,'KYC','PENDING',?)",UUID.randomUUID(),workflow,UUID.randomUUID());
            }
        });
        long actions=count("action_request"),audit=count("audit_event");UUID actionId=UUID.randomUUID();
        var failure=assertThrows(ApiException.class,()->workflows.start(new Actor("customer-102","CUSTOMER",Set.of("customer-102")),actionId,new StartWorkflowRequest("APP-DEMO-102-001","customer-102",1000000L,UUID.fromString("00000000-0000-4000-8000-000000000102"))));
        assertEquals(429,failure.status());assertEquals("RATE_LIMITED",failure.reasonCode());
        assertEquals(1000,count("workflow"));assertEquals(1000,count("workflow_job"));assertEquals(1000,count("loan_application"));
        assertEquals(actions,count("action_request"));assertEquals(audit,count("audit_event"));assertEquals(0,count("risk_ledger"));assertEquals(0,count("mock_payment"));
        // Claiming an existing item releases one admission slot. Retry retains the original action ID.
        tx.executeWithoutResult(s->{db.gate();db.update("UPDATE workflow_job SET state='FAILED' WHERE id=(SELECT id FROM workflow_job ORDER BY id LIMIT 1)");});
        assertDoesNotThrow(()->workflows.start(new Actor("customer-102","CUSTOMER",Set.of("customer-102")),actionId,new StartWorkflowRequest("APP-DEMO-102-001","customer-102",1000000L,UUID.fromString("00000000-0000-4000-8000-000000000102"))));
        assertEquals(1000,((Number)db.required("SELECT count(*) AS n FROM workflow_job WHERE state='PENDING'").get("n")).intValue());
    }
    private long count(String table){return ((Number)db.required("SELECT count(*) AS n FROM "+table).get("n")).longValue();}
    private boolean sqlState(Throwable failure,String state){for(Throwable t=failure;t!=null;t=t.getCause())if(t instanceof java.sql.SQLException sql && state.equals(sql.getSQLState()))return true;return false;}
}
