package com.finsec.fuse.integration;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.DevActorRegistry;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.policy.*;
import com.finsec.fuse.quarantine.*;
import com.finsec.fuse.workflow.JobWorker;
import com.finsec.fuse.workflow.StartWorkflowRequest;
import jakarta.servlet.Filter;
import java.util.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/** Independent synthetic inputs. Queue cancellation and authenticated lineage admission are separate oracles. */
class QueuedQuarantineParentReuseIT extends PaymentFixture {
    private static final String LOAN_ACTION="CREATE_LOAN_RECOMMENDATION";
    private static final List<String> TABLES=List.of("demo_auth_registry","demo_token","execution_gate","loan_application","workflow","workflow_stage",
            "workflow_job","agent_run","agent_result","run_source_use","run_evidence_use","run_dependency",
            "delegation_grant","approval","payment_reservation","risk_ledger","mock_payment","quarantine",
            "quarantine_workflow_hold","action_request","audit_event","trusted_evidence","source_document_version");
    @Autowired WebApplicationContext context;
    @Autowired DevActorRegistry actors;
    @Autowired JobWorker worker;
    @Autowired DelegationService grants;
    @Autowired GrantCodec codec;
    MockMvc mvc;
    String reviewerToken;

    @BeforeEach void authenticatedReviewer() {
        var filters=new ArrayList<Filter>(context.getBeansOfType(Filter.class).values());
        AnnotationAwareOrderComparator.sort(filters);
        mvc=MockMvcBuilders.webAppContextSetup(context).addFilters(filters.toArray(Filter[]::new)).build();
        reviewerToken=DevActorRegistry.generateToken();
        issueToken(reviewerToken,new Actor("queued-reviewer-"+UUID.randomUUID(),"LOAN_REVIEWER",Set.of("customer-102")));
    }

    @Test void sourceQuarantineCancelsActuallyQueuedLoanWithoutDispatchAndRecoveryUsesFreshParents() throws Exception {
        // An independent, valid application is already waiting for approval on reviewed version 1.
        UUID independent=startRegistered("customer-103");
        var safe=prepareKyc();kyc.apply(safe,verified(safe));
        var safeLoan=jobs.claim().orElseThrow();loans.execute(safeLoan.jobId(),safeLoan.token());
        assertEquals("WAIT_APPROVAL",str(workflow(independent),"state"));
        tx.executeWithoutResult(status->{db.gate();db.update("update application_registry set document_version=2 where customer_id='customer-102'");});
        UUID affected=start("customer-102");
        var original=prepareKyc();kyc.apply(original,verified(original));
        UUID parent=uuid(workflow(affected),"current_kyc_result_id");
        assertEquals("VALIDATED",str(db.required("select * from agent_result where id=?",parent),"status"));
        var queued=db.required("select * from workflow_job where workflow_id=? and phase='LOAN'",affected);
        UUID job=uuid(queued,"id"),jobAction=uuid(queued,"execution_action_id");
        assertEquals("PENDING",str(queued,"state"));
        assertNull(queued.get("lease_token"));assertNull(queued.get("started_at"));assertNull(queued.get("run_id"));
        assertEquals(1,scalar("select count(*) n from run_source_use where run_id=? and document_id=? and document_version=2",original.input().runId(),DOCUMENT));
        assertRisk(affected,10,0);
        var before=snapshot();var independentBefore=workflowSnapshot(independent);
        var history=rows("risk_ledger");var affectedRisk=workflowSnapshot(affected).get("risk_ledger");
        var auditHistory=rows("audit_event");
        UUID incident=quarantineVersionTwo();
        var after=snapshot();
        for(String table:TABLES) {
            if(!Set.of("execution_gate","workflow","workflow_job","agent_result","quarantine","action_request","audit_event").contains(table))
                assertEquals(before.get(table),after.get(table),table+" has no quarantine side effect for an unstarted Loan");
        }
        assertEquals(before.get("quarantine").size()+1,after.get("quarantine").size());
        assertEquals(before.get("action_request").size()+1,after.get("action_request").size());
        assertEquals(before.get("audit_event").size()+2,after.get("audit_event").size());
        assertTrue(after.get("audit_event").containsAll(auditHistory));
        assertEquals(independentBefore,workflowSnapshot(independent));
        assertEquals(history,rows("risk_ledger"));
        assertEquals("INVALIDATED",str(db.required("select * from agent_result where id=?",parent),"status"));
        assertEquals("BLOCKED",str(workflow(affected),"state"));assertRisk(affected,10,0);
        var cancelled=db.required("select * from workflow_job where id=?",job);
        assertEquals("FAILED",str(cancelled,"state"));assertEquals("QUARANTINED",str(cancelled,"last_error"));
        assertNull(cancelled.get("lease_token"));assertNull(cancelled.get("run_id"));assertNull(cancelled.get("started_at"));
        assertNotNull(cancelled.get("completed_at"));
        assertFalse(worker.runOne(),"Quarantine cancels the actual queue item before any dispatch; do not manufacture a lease");
        assertEquals(after,snapshot(),"An empty worker poll must not create an audit, action receipt, charge or result");
        assertEquals(0,scalar("select count(*) n from audit_event where action_id=?",jobAction));
        assertEquals(0,scalar("select count(*) n from action_request where action_id=?",jobAction));
        assertEquals(0,scalar("select count(*) n from agent_run where workflow_id=? and role='LOAN'",affected));
        assertEquals(0,events("RELEASE"));assertEquals(0,events("REFUND"));
        assertEquals(0,count("approval"));assertEquals(0,count("payment_reservation"));assertEquals(0,count("mock_payment"));

        // The real bearer is an in-scope reviewer, confirmed by a successful trace read.
        mvc.perform(get("/api/v1/workflows/"+affected+"/trace").header("Authorization",bearer()))
                .andExpect(status().isOk());
        UUID deniedAction=UUID.randomUUID();
        mvc.perform(post("/api/v1/workflows/"+affected+"/resume").header("Authorization",bearer())
                .header("Idempotency-Key",deniedAction).contentType(MediaType.APPLICATION_JSON)
                .content(json.write(new ResumeRequest(1,"Attempt to reuse the existing evaluation"))))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.reasonCodes[0]").value("QUARANTINED"));
        assertEquals(after,snapshot(),"Authenticated recovery rejection is read-only, including denied action receipts");

        var independentPay=approve(independent);paymentAgent.execute(independentPay.jobId(),independentPay.token());
        assertEquals("PAID",str(workflow(independent),"state"));assertRisk(independent,85,0);
        var paidIndependent=workflowSnapshot(independent);
        release(incident);
        assertEquals("BLOCKED",str(workflow(affected),"state"));
        assertEquals("INVALIDATED",str(db.required("select * from agent_result where id=?",parent),"status"));
        assertRisk(affected,10,0);assertEquals(affectedRisk,workflowSnapshot(affected).get("risk_ledger"));
        mvc.perform(post("/api/v1/workflows/"+affected+"/resume").header("Authorization",bearer())
                .header("Idempotency-Key",UUID.randomUUID()).contentType(MediaType.APPLICATION_JSON)
                .content(json.write(new ResumeRequest(1,"Reviewed safe source and independent evidence"))))
                .andExpect(status().isAccepted()).andExpect(jsonPath("$.generation").value(2));
        assertNull(workflow(affected).get("current_kyc_result_id"));
        var fresh=prepareKyc();assertEquals(2,fresh.input().generation());
        assertEquals(1,fresh.input().documents().getFirst().documentVersion());
        kyc.apply(fresh,verified(fresh));
        var freshLoan=jobs.claim().orElseThrow();assertEquals("LOAN",freshLoan.phase());loans.execute(freshLoan.jobId(),freshLoan.token());
        UUID freshParent=uuid(workflow(affected),"current_kyc_result_id");assertNotEquals(parent,freshParent);
        assertEquals(0,scalar("select count(*) n from run_dependency where parent_result_id=?",parent));
        assertEquals(1,scalar("select count(*) n from run_dependency where parent_result_id=?",freshParent));
        var pay=approve(affected);paymentAgent.execute(pay.jobId(),pay.token());
        assertEquals("PAID",str(workflow(affected),"state"));assertRisk(affected,85,0);
        assertEquals(2,count("mock_payment"));assertEquals(0,events("RELEASE"));assertEquals(0,events("REFUND"));
        assertEquals(2,scalar("select count(*) n from risk_ledger where workflow_id=? and event_type='CHARGE'",affected));
        assertEquals(1,scalar("select count(*) n from risk_ledger where workflow_id=? and event_type='CONSUME'",affected));
        assertEquals("INVALIDATED",str(db.required("select * from agent_result where id=?",parent),"status"));
        assertEquals(paidIndependent,workflowSnapshot(independent));assertFalse(worker.runOne());
    }

    @Test void authenticInScopeParentReplayIsRevokedAndReleaseCannotMakeInvalidatedParentReusable() {
        tx.executeWithoutResult(status->{db.gate();db.update("update application_registry set document_version=2 where customer_id='customer-102'");});
        UUID workflow=start("customer-102");var p=prepareKyc();kyc.apply(p,verified(p));
        UUID parent=uuid(workflow(workflow),"current_kyc_result_id");
        // Admission-only fixture: Loan normally issues and consumes in one transaction. No fake lease or dispatch.
        var target=newTarget(workflow,1);
        var transport=tx.execute(status->{db.gate();db.lockWorkflow(workflow);return issue(target,parent);});
        var authentic=codec.verify(transport).claims();
        assertEquals(parent,authentic.sourceResultId());assertEquals("KYC",authentic.sourceAgent());
        assertEquals("customer-102",authentic.customerId());
        assertEquals(authentic,tx.execute(status->{db.gate();db.lockWorkflow(workflow);
            return grants.validate(transport,"KYC",workflow,target.runId(),LOAN_ACTION,clock.now());}));
        UUID incident=quarantineVersionTwo();
        assertEquals("INVALIDATED",str(db.required("select * from agent_result where id=?",parent),"status"));
        assertEquals("REVOKED",str(db.required("select * from delegation_grant where id=?",authentic.grantId()),"status"));
        var before=snapshot();
        // HMAC authentication still succeeds. Denial is policy revocation, not a forged token or foreign workflow.
        assertEquals(authentic,codec.verify(transport).claims());
        tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflow);
            assertEquals("SCOPE_EXCEEDED",assertThrows(PolicyException.class,()->
                grants.validate(transport,"KYC",workflow,target.runId(),LOAN_ACTION,clock.now())).reasonCode());});
        assertEquals(before,snapshot());
        release(incident);
        // Fresh valid target/action, same current generation, consumed authentic parent, no active incident.
        // This reaches invalidated-result lineage checks rather than revoked-child or quarantine checks.
        var fresh=newTarget(workflow,2);var released=snapshot();
        assertEquals(1,integer(workflow(workflow),"generation"));
        assertNotEquals(target.actionId(),fresh.actionId());
        assertEquals("QUEUED",str(db.required("select * from agent_run where id=?",fresh.runId()),"status"));
        assertEquals("INVALIDATED",str(db.required("select * from agent_result where id=?",parent),"status"));
        var parentGrant=db.required("select * from delegation_grant where target_run_id=?",p.input().runId());
        assertEquals("CONSUMED",str(parentGrant,"status"));
        assertEquals(p.input().runId(),codec.verify(grants.transport(uuid(parentGrant,"id"))).claims().targetRunId());
        assertEquals(parent,uuid(workflow(workflow),"current_kyc_result_id"));
        assertEquals("VALIDATED",str(db.required("select * from agent_run where id=?",p.input().runId()),"status"));
        assertEquals(0,scalar("select count(*) n from quarantine where status='ACTIVE'"));
        tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflow);
            assertEquals("CONTEXT_MISMATCH",assertThrows(PolicyException.class,()->issue(fresh,parent)).reasonCode());});
        assertEquals(released,snapshot(),"Commit after caught denial, so rollback cannot hide accidental side effects");
        assertEquals(0,scalar("select count(*) n from delegation_grant where target_run_id=?",fresh.runId()));
        assertRisk(workflow,10,0);assertEquals(0,count("run_dependency"));
        assertEquals(0,count("approval"));assertEquals(0,count("payment_reservation"));assertEquals(0,count("mock_payment"));
        assertEquals(0,events("RELEASE"));assertEquals(0,events("REFUND"));assertFalse(worker.runOne());
    }

    private record Target(UUID workflowId,UUID runId,UUID actionId,byte[] bytes) {}
    private Target newTarget(UUID workflowId,int index) {
        return tx.execute(status->{db.gate();var w=db.lockWorkflow(workflowId);
            UUID run=UUID.randomUUID(),action=UUID.randomUUID();
            byte[] bytes=json.bytes(Json.ordered("workflowId",workflowId,"generation",integer(w,"generation"),
                    "kycResultId",uuid(w,"current_kyc_result_id")));
            db.update("insert into agent_run(id,workflow_id,generation,role,agent_id,agent_version,run_index,status,action_id,input_bytes,input_snapshot_hash) values(?,?,?,'LOAN','LOAN',1,?,'QUEUED',?,?,?)",
                    run,workflowId,integer(w,"generation"),index,action,bytes,Json.sha256(bytes));
            return new Target(workflowId,run,action,bytes);
        });
    }
    private GrantTransport issue(Target target,UUID result) {
        var parent=db.required("select * from agent_result where id=?",result);
        var grant=db.required("select * from delegation_grant where target_run_id=? and status='CONSUMED'",uuid(parent,"run_id"));
        return grants.issue(target.workflowId(),"LOAN",uuid(parent,"run_id"),target.runId(),result,uuid(grant,"id"),
                target.actionId(),null,str(parent,"evidence_bundle_hash"),target.bytes(),clock.now());
    }
    private UUID quarantineVersionTwo() {
        return (UUID)quarantines.apply(SECURITY,UUID.randomUUID(),new QuarantineRequest(QuarantineRequest.Scope.SOURCE_VERSION,
                null,null,null,DOCUMENT,2,null,null,QuarantineRequest.Reason.SOURCE_COMPROMISED,"Synthetic source-version investigation")).get("quarantineId");
    }
    private void release(UUID incident) {
        var evidence=db.query("select id from trusted_evidence where customer_id='customer-102' order by id").stream().map(row->uuid(row,"id")).toList();
        quarantines.release(SECURITY,incident,UUID.randomUUID(),new ReleaseRequest(new ReleaseRequest.Remediation(
                DOCUMENT,1,evidence,null,null,"Reviewed safe version and independently validated evidence")));
    }
    private UUID startRegistered(String customer) {
        var registered=db.required("select * from application_registry where customer_id=?",customer);
        String reference="QUEUED-INDEPENDENT-"+customer;
        db.update("insert into application_registry(business_reference,customer_id,amount_krw,payout_account_id,document_id,document_version) values(?,?,300000,?,?,1)",
                reference,customer,uuid(registered,"payout_account_id"),DOCUMENT);
        return (UUID)workflows.start(new Actor(customer,"CUSTOMER",Set.of(customer)),UUID.randomUUID(),new StartWorkflowRequest(
                reference,customer,300_000L,uuid(registered,"payout_account_id"))).get("workflowId");
    }
    private String bearer(){return "Bearer "+reviewerToken;}
    private long scalar(String sql,Object... args){return ((Number)db.required(sql,args).get("n")).longValue();}
    private List<String> rows(String table){return db.jdbc().queryForList("select to_jsonb(t)::text from "+table+" t order by to_jsonb(t)::text",String.class);}
    private Map<String,List<String>> snapshot(){var out=new LinkedHashMap<String,List<String>>();for(String table:TABLES)out.put(table,rows(table));return out;}
    private Map<String,List<String>> workflowSnapshot(UUID id) {
        var out=new LinkedHashMap<String,List<String>>();
        for(String table:List.of("workflow","workflow_stage","workflow_job","agent_run","agent_result","delegation_grant",
                "approval","payment_reservation","risk_ledger","mock_payment","run_dependency","audit_event","action_request"))
            out.put(table,db.jdbc().queryForList("select to_jsonb(t)::text from "+table+" t where "+(table.equals("workflow")?"id":"workflow_id")+"=? order by to_jsonb(t)::text",String.class,id));
        return out;
    }
}
