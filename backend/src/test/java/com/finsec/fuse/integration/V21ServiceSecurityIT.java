package com.finsec.fuse.integration;

import com.finsec.fuse.auth.*;
import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.testing.DemoTokenFixtureOracle;
import com.finsec.fuse.experiments.*;
import com.finsec.fuse.payment.*;
import com.finsec.fuse.persistence.ActionRequests;
import com.finsec.fuse.quarantine.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.http.MediaType;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Public authentication plus actual service/PG boundaries; not a claim of all SC branches. */
class V21ServiceSecurityIT extends PaymentFixture {
    MockMvc mvc;
    @Autowired WebApplicationContext context;
    @BeforeEach void configureRealMvcAndFilters() {
        var filters=new ArrayList<Filter>(context.getBeansOfType(Filter.class).values());
        AnnotationAwareOrderComparator.sort(filters);
        mvc=MockMvcBuilders.webAppContextSetup(context).addFilters(filters.toArray(Filter[]::new)).build();
    }
    @Autowired DevActorRegistry actors;
    @Autowired ActionRequests actions;
    @Autowired ExperimentRegistry experiments;

    private record Identity(String token, Actor actor) {}
    private Identity identity(String role, String... customers) {
        String token=DevActorRegistry.generateToken();
        Actor actor=new Actor("qa-"+UUID.randomUUID(),role,Set.of(customers));
        authOracle().issue(token,actor);return new Identity(token,actor);
    }
    private String bearer(Identity who){return "Bearer "+who.token();}
    private Map<String,Object> counts() {
        var result=new LinkedHashMap<String,Object>();
        for(String table:List.of("workflow","agent_run","workflow_job","approval","mock_payment","risk_ledger","quarantine","action_request","audit_event"))
            result.put(table,count(table));
        for(String table:List.of("demo_auth_registry","demo_token"))result.put(table,rows(table));
        return result;
    }
    private List<String> rows(String table) {
        return db.jdbc().queryForList("SELECT to_jsonb(t)::text FROM \""+table.replace("\"","\"\"")+"\" t ORDER BY to_jsonb(t)::text",String.class);
    }
    private Map<String,List<String>> fullRows() {
        var result=new LinkedHashMap<String,List<String>>();
        for(String table:db.jdbc().queryForList("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name",String.class))
            result.put(table,rows(table));
        assertTrue(result.keySet().containsAll(List.of("demo_auth_registry","demo_token")));
        return result;
    }
    private DemoTokenFixtureOracle authOracle() { return new DemoTokenFixtureOracle(tokenFixture,json,this::fullRows); }
    private void denied(MockHttpServletRequestBuilder request,int status) throws Exception {
        var before=fullRows();
        String response=mvc.perform(request).andExpect(status().is(status)).andReturn().getResponse().getContentAsString();
        assertFalse(response.contains("reviewSnapshotHash"));assertFalse(response.contains("approvalId"));
        assertFalse(response.contains("paymentId"));assertFalse(response.contains("receipt_json"));
        assertEquals(before,fullRows(),"Denied HTTP request must preserve all business and auth rows");
    }
    @Test void originalReviewerScopeAndRevocationAreCheckedBeforeHistoricalApprovalReplay() throws Exception {
        UUID workflow=ready102(),action=UUID.randomUUID();
        Identity reviewer=identity("LOAN_REVIEWER","customer-102");
        String hash=(String)approvals.preview(reviewer.actor(),workflow).get("reviewSnapshotHash");
        var request=new ApprovalRequest(ApprovalRequest.Decision.APPROVE,hash,"Reviewed mock application");
        String body=json.write(request),path="/api/v1/workflows/"+workflow+"/approvals";
        mvc.perform(post(path).header("Authorization",bearer(reviewer)).header("Idempotency-Key",action).contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isCreated());
        var job=jobs.claim().orElseThrow();paymentAgent.execute(job.jobId(),job.token());
        assertEquals("PAID",workflow(workflow).get("state"));assertRisk(workflow,85,0);
        clock.set(clock.now().plusSeconds(3600)); // Historical reply remains valid after approval/evidence expiry.
        mvc.perform(post(path).header("Authorization",bearer(reviewer)).header("Idempotency-Key",action).contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isCreated()).andExpect(jsonPath("$.replayed").value(true));
        Identity other=identity("LOAN_REVIEWER","customer-101");
        Identity otherInScope=identity("LOAN_REVIEWER","customer-102");
        var before=counts();
        denied(post(path).header("Authorization",bearer(other)).header("Idempotency-Key",action).contentType(MediaType.APPLICATION_JSON).content(body),403);
        denied(post(path).header("Authorization",bearer(otherInScope)).header("Idempotency-Key",action).contentType(MediaType.APPLICATION_JSON).content(body),403);
        assertEquals(403,assertThrows(ApiException.class,()->approvals.decide(otherInScope.actor(),workflow,action,request)).status());
        assertEquals(before,counts());
        authOracle().updateScope(reviewer.actor().actorId(),Set.of("customer-101"));before=counts();
        denied(post(path).header("Authorization",bearer(reviewer)).header("Idempotency-Key",action).contentType(MediaType.APPLICATION_JSON).content(body),403);
        Actor current=actors.resolve(reviewer.token());
        assertEquals(403,assertThrows(ApiException.class,()->approvals.decide(current,workflow,action,request)).status());
        assertEquals(before,counts());
        authOracle().updateScope(reviewer.actor().actorId(),Set.of("customer-102"));
        authOracle().revoke(reviewer.actor().actorId());before=counts();
        denied(post(path).header("Authorization",bearer(reviewer)).header("Idempotency-Key",action).contentType(MediaType.APPLICATION_JSON).content(body),401);
        assertEquals(before,counts());assertEquals(1,count("mock_payment"));assertEquals(1,events("CONSUME"));assertRisk(workflow,85,0);
    }
    @Test void ambiguousPublicHeadersRejectBeforeAnyDatabaseEffects() throws Exception {
        Identity customer=identity("CUSTOMER","customer-102");
        String body="{\"businessReference\":\"APP-DEMO-102-001\",\"customerId\":\"customer-102\",\"amountKrw\":1000000,\"payoutAccountId\":\"00000000-0000-4000-8000-000000000102\"}";
        String key=UUID.randomUUID().toString();var before=counts();
        var requests=List.of(
            post("/api/v1/workflows").header("Authorization",bearer(customer),bearer(customer)).header("Idempotency-Key",key),
            post("/api/v1/workflows").header("Authorization",bearer(customer)+", "+bearer(customer)).header("Idempotency-Key",key),
            post("/api/v1/workflows").header("Authorization",bearer(customer)).header("Idempotency-Key",key,key),
            post("/api/v1/workflows").header("Authorization",bearer(customer)).header("Idempotency-Key",key+","+key));
        for(var request:requests) mvc.perform(request.contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isBadRequest()).andExpect(jsonPath("$.reasonCodes[0]").value("INVALID_REQUEST"));
        assertEquals(before,counts());
    }
    @Test void currentScopesControlCustomerDetailTracePreviewAndListAgainstActualRows() throws Exception {
        UUID workflow=ready102();Identity customer=identity("CUSTOMER","customer-101"),owner=identity("CUSTOMER","customer-102");
        Identity reviewer=identity("LOAN_REVIEWER","customer-102"),developer=identity("DEVELOPER");
        var before=counts();String path="/api/v1/workflows/"+workflow;
        denied(get(path).header("Authorization",bearer(customer)),403);
        mvc.perform(get(path).header("Authorization",bearer(owner))).andExpect(status().isOk()).andExpect(jsonPath("$.customerId").value("customer-102"));
        denied(get(path+"/trace").header("Authorization",bearer(owner)),403);
        mvc.perform(get(path+"/trace").header("Authorization",bearer(reviewer))).andExpect(status().isOk()).andExpect(jsonPath("$.runs.length()").value(2));
        assertEquals(before,counts());
        authOracle().updateScope(reviewer.actor().actorId(),Set.of("customer-101"));before=counts();
        for(String suffix:List.of("","/trace","/approval-preview"))denied(get(path+suffix).header("Authorization",bearer(reviewer)),403);
        mvc.perform(get("/api/v1/workflows").header("Authorization",bearer(reviewer))).andExpect(status().isOk()).andExpect(jsonPath("$.total").value(0));
        denied(get(path).header("Authorization",bearer(developer)),403);
        assertEquals(before,counts());assertEquals("WAIT_APPROVAL",workflow(workflow).get("state"));
    }
    @Test void securityScopeWithdrawalBlocksStoredQuarantineReplyAndImpactAndRelease() throws Exception {
        UUID workflow=ready102(),action=UUID.randomUUID();Identity security=identity("SECURITY_OPERATOR","customer-102");
        var request=new QuarantineRequest(QuarantineRequest.Scope.WORKFLOW,null,null,workflow,null,null,null,null,QuarantineRequest.Reason.SECURITY_INVESTIGATION,"Mock investigation");
        UUID incident=(UUID)quarantines.apply(security.actor(),action,request).get("quarantineId");
        mvc.perform(get("/api/v1/incidents/"+incident+"/impact").header("Authorization",bearer(security))).andExpect(status().isOk());
        authOracle().updateScope(security.actor().actorId(),Set.of("customer-101"));var before=counts();
        denied(post("/api/v1/quarantines").header("Authorization",bearer(security)).header("Idempotency-Key",action).contentType(MediaType.APPLICATION_JSON).content(json.write(request)),403);
        denied(get("/api/v1/incidents/"+incident+"/impact").header("Authorization",bearer(security)),403);
        var ids=db.query("SELECT id FROM trusted_evidence WHERE customer_id='customer-102'").stream().map(row->(UUID)row.get("id")).toList();
        var release=new ReleaseRequest(new ReleaseRequest.Remediation(DOCUMENT,1,ids,null,null,"Mock release"));
        denied(post("/api/v1/quarantines/"+incident+"/release").header("Authorization",bearer(security)).header("Idempotency-Key",UUID.randomUUID()).contentType(MediaType.APPLICATION_JSON).content(json.write(release)),403);
        assertEquals(before,counts());assertEquals("ACTIVE",db.required("SELECT status FROM quarantine WHERE id=?",incident).get("status"));
    }
    @Test void actualExperimentServiceReadsOnlyOwnersPersistedRecord() {
        Identity owner=identity("DEVELOPER"),other=identity("DEVELOPER");UUID id=UUID.randomUUID();
        // Persist a report fixture, not a fabricated claim that an experiment ran.
        db.update("INSERT INTO experiment(id,actor_id,fixture_set_id,mode,model_mode,repeat_count,case_ids,status,total_runs,config_json) VALUES(?,?,'mvp-security-v1','PAIRED','REPLAY',1,'[\"T02_MISSING_EVIDENCE\"]'::jsonb,'INTERRUPTED',2,'{}'::jsonb)",id,owner.actor().actorId());
        try(var service=newService()) {
            assertEquals(id,service.value.get(owner.actor(),id).get("experimentId"));
            assertEquals(404,assertThrows(ApiException.class,()->service.value.get(other.actor(),id)).status());
            assertEquals(403,assertThrows(ApiException.class,()->service.value.get(REVIEWER,id)).status());
            assertEquals(1,count("experiment"));assertEquals(0,count("experiment_case_result"));assertEquals(0,count("mock_payment"));
        }
    }
    private ServiceResource newService(){return new ServiceResource(new ExperimentService(db,json,actions,experiments,tx,new MockEnvironment(),input->{throw new AssertionError("Read must not call model");}));}
    private record ServiceResource(ExperimentService value) implements AutoCloseable {public void close(){value.close();}}
}
