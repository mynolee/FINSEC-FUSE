package com.finsec.fuse.integration;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.DevActorRegistry;
import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.quarantine.QuarantineRequest;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import static org.junit.jupiter.api.Assertions.*;

/** Independent synthetic fixtures, real PostgreSQL aggregates and authenticated loopback HTTP. */
@SpringBootTest(classes=FuseApplication.class,webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
class ImpactPotentialAmountIT extends PaymentFixture {
    private static final UUID ACCOUNT=UUID.fromString("00000000-0000-4000-8000-000000000102");
    private static final List<String> ELIGIBLE=List.of("KYC_PENDING","KYC_VALIDATED","REVIEW_READY","WAIT_APPROVAL",
        "APPROVED","PAYMENT_RESERVED","BLOCKED","ON_HOLD");
    @Autowired DevActorRegistry actors;
    @Value("${local.server.port}") int port;
    private final HttpClient http=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @Test void countAndAmountShareExactEligibleScopeAndUseRequestedAmountsRatherThanLimits() {
        UUID incident=sourceIncident();long expected=0;
        for(int i=0;i<ELIGIBLE.size();i++) {
            // Equal amounts in different applications must both count, not SUM(DISTINCT amount).
            long amount=123_457L+(i/2);expected+=amount;
            hold(incident,application(ELIGIBLE.get(i),amount),1);
        }
        hold(incident,application("PAID",40_000_000L),1);
        hold(incident,application("REJECTED",30_000_000L),1);
        application("ON_HOLD",20_000_000L); // Same customer and document, no incident linkage.
        registryOnly(); // Same customer/document, but not a submitted application.
        assertPotential(incident,8,Long.toString(expected));
        assertNotEquals(8*50_000_000L,expected);
    }

    @Test void historicalRunsRetriesMultipleHoldsAndEventsDoNotMultiplyOneApplication() {
        UUID workflow=ready102();UUID incident=sourceIncident();UUID original=kycRun(workflow),retry=UUID.randomUUID();
        tx.executeWithoutResult(status->{
            db.gate();
            db.update("insert into agent_run(id,workflow_id,generation,role,agent_id,agent_version,run_index,status,action_id,started_at) "+
                "select ?,workflow_id,generation,role,agent_id,agent_version,run_index+1,'FAILED',?,started_at from agent_run where id=?",
                retry,UUID.randomUUID(),original);
            db.update("insert into run_source_use(run_id,document_id,document_version,content_hash) select ?,document_id,document_version,content_hash from run_source_use where run_id=?",retry,original);
            db.update("update workflow set generation=2,state='ON_HOLD',current_kyc_result_id=null,current_loan_result_id=null where id=?",workflow);
            for(int i=0;i<3;i++)db.update("insert into audit_event(id,workflow_id,quarantine_id,actor_id,event_type,details_json) values(?,?,?,'fixture','RETRY_OBSERVED','{}'::jsonb)",UUID.randomUUID(),workflow,incident);
        });
        hold(incident,workflow,1);hold(incident,workflow,2);
        var impact=quarantines.impact(SECURITY,incident);
        assertTrue(((Collection<?>)impact.get("historicalRunIds")).size()>1);
        assertPotential(incident,1,"1000000");
        long audits=count("audit_event"),applications=count("loan_application");
        assertPotential(incident,1,"1000000");
        assertEquals(audits,count("audit_event"));assertEquals(applications,count("loan_application"));
    }

    @Test void currentStateRatherThanHistoricalStatusControlsEligibility() {
        UUID incident=sourceIncident();UUID workflow=application("ON_HOLD",765_432L);hold(incident,workflow,1);
        assertPotential(incident,1,"765432");
        for(String state:List.of("PAID","REJECTED")) {
            state(workflow,state);assertPotential(incident,0,"0");
        }
        state(workflow,"BLOCKED");assertPotential(incident,1,"765432");
    }

    @Test void noLinkedApplicationsReturnsExplicitZeroAndCurrencyDespiteRegistryEntries() {
        UUID incident=sourceIncident();registryOnly();
        assertTrue(count("application_registry")>0);assertPotential(incident,0,"0");
    }

    @Test void sourcePolicyHoldBeforeAnyRunExistsContributesTheSubmittedApplication() {
        UUID incident=sourceIncident();UUID workflow=start("customer-102");
        var lease=jobs.claim().orElseThrow();assertTrue(kyc.prepare(lease.jobId(),lease.token()).isEmpty());
        assertEquals(0,count("agent_run"));assertEquals(0,count("run_source_use"));
        var impact=quarantines.impact(SECURITY,incident);
        assertTrue(((Collection<?>)impact.get("policyHeldWorkflowIds")).contains(workflow));
        assertPotential(incident,1,"1000000");
    }

    @Test void agentPolicyHoldBeforeAnyRunExistsContributesTheSubmittedApplication() {
        UUID incident=(UUID)quarantines.apply(SECURITY,UUID.randomUUID(),new QuarantineRequest(
            QuarantineRequest.Scope.AGENT_VERSION,null,null,null,null,null,"KYC",1,
            QuarantineRequest.Reason.AGENT_COMPROMISED,"Synthetic agent hold")).get("quarantineId");
        UUID workflow=start("customer-102");var lease=jobs.claim().orElseThrow();
        assertTrue(kyc.prepare(lease.jobId(),lease.token()).isEmpty());
        assertEquals(0,count("agent_run"));assertEquals(0,count("run_source_use"));
        var impact=quarantines.impact(SECURITY,incident);
        assertTrue(((Collection<?>)impact.get("policyHeldWorkflowIds")).contains(workflow));
        assertPotential(incident,1,"1000000");
    }

    @Test void aggregateExceedsSignedIntegerWithoutOverflowOrJsonNumberCoercion() {
        UUID incident=sourceIncident();
        for(int i=0;i<50;i++)hold(incident,application("ON_HOLD",50_000_000L),1);
        assertPotential(incident,50,"2500000000");
        var parsed=json.map(json.write(quarantines.impact(SECURITY,incident)));
        assertEquals("2500000000",((Map<?,?>)parsed.get("potential")).get("totalAmountKrw"));
    }

    @Test void publicResponseKeepsExactStringCurrencyAndExistingRoleAndCustomerScope() throws Exception {
        UUID workflow=start("customer-102");
        UUID incident=(UUID)quarantines.apply(SECURITY,UUID.randomUUID(),new QuarantineRequest(
            QuarantineRequest.Scope.WORKFLOW,null,null,workflow,null,null,null,null,
            QuarantineRequest.Reason.SECURITY_INVESTIGATION,"Synthetic amount contract")).get("quarantineId");
        String path="/api/v1/incidents/"+incident+"/impact";
        var response=get(path,token("SECURITY_OPERATOR","customer-102"));assertEquals(200,response.statusCode());
        var potential=(Map<?,?>)json.map(response.body()).get("potential");
        assertEquals("1000000",potential.get("totalAmountKrw"));assertEquals("KRW",potential.get("currency"));
        assertEquals(1,((Number)potential.get("applicationCount")).intValue());
        for(String role:List.of("CUSTOMER","LOAN_REVIEWER","DEVELOPER"))assertEquals(403,get(path,token(role,"customer-102")).statusCode());
        var restricted=get(path,token("SECURITY_OPERATOR","customer-101"));assertEquals(403,restricted.statusCode());
        assertFalse(restricted.body().contains("totalAmountKrw"));assertFalse(restricted.body().contains("1000000"));
        assertEquals(401,get(path,null).statusCode());
    }

    private UUID sourceIncident() {
        return (UUID)quarantines.apply(SECURITY,UUID.randomUUID(),new QuarantineRequest(
            QuarantineRequest.Scope.SOURCE_VERSION,null,null,null,DOCUMENT,1,null,null,
            QuarantineRequest.Reason.SOURCE_COMPROMISED,"Synthetic scope fixture")).get("quarantineId");
    }
    private String registryOnly() {
        String reference="IMPACT-"+UUID.randomUUID();
        tx.executeWithoutResult(status->{db.gate();db.update("insert into application_registry(business_reference,customer_id,amount_krw,payout_account_id,document_id,document_version) values(?,'customer-102',50000000,?,?,1)",reference,ACCOUNT,DOCUMENT);});
        return reference;
    }
    private UUID application(String state,long amount) {
        String reference=registryOnly();UUID application=UUID.randomUUID(),workflow=UUID.randomUUID();
        // Reader-level fixture deliberately differs from registry amount to identify the authoritative column.
        tx.executeWithoutResult(status->{db.gate();
            db.update("insert into loan_application(id,business_reference,customer_id,amount_krw,payout_account_id) values(?,?,'customer-102',?,?)",application,reference,amount,ACCOUNT);
            db.update("insert into workflow(id,application_id,root_authorization_id,risk_ledger_id,principal_id,policy_version,state) values(?,?,?,?,'customer-102','FUSE-POLICY-1',?)",workflow,application,UUID.randomUUID(),UUID.randomUUID(),state);
        });return workflow;
    }
    private void hold(UUID incident,UUID workflow,int generation) {
        tx.executeWithoutResult(status->{db.gate();db.update("insert into quarantine_workflow_hold(quarantine_id,workflow_id,generation) values(?,?,?)",incident,workflow,generation);});
    }
    private void state(UUID workflow,String state) {
        tx.executeWithoutResult(status->{db.gate();db.update("update workflow set state=? where id=?",state,workflow);});
    }
    private void assertPotential(UUID incident,long count,String amount) {
        var potential=(Map<?,?>)quarantines.impact(SECURITY,incident).get("potential");
        assertEquals(count,((Number)potential.get("applicationCount")).longValue());
        assertInstanceOf(String.class,potential.get("totalAmountKrw"));
        assertEquals(amount,potential.get("totalAmountKrw"));assertEquals("KRW",potential.get("currency"));
        assertTrue(((String)potential.get("totalAmountKrw")).matches("0|[1-9][0-9]*"));
        for(String field:List.of("roles","maxDownstreamDepth","registeredCustomerCount","perApplicationLimitKrw","missingPolicyFields"))assertTrue(potential.containsKey(field),field);
    }
    private String token(String role,String customer) {
        String token=DevActorRegistry.generateToken();issueToken(token,new Actor("impact-"+UUID.randomUUID(),role,Set.of(customer)));return token;
    }
    private HttpResponse<String> get(String path,String token) throws Exception {
        var request=HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+path)).timeout(Duration.ofSeconds(10));
        if(token!=null)request.header("Authorization","Bearer "+token);
        return http.send(request.GET().build(),HttpResponse.BodyHandlers.ofString());
    }
}
