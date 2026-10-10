package com.finsec.fuse.integration;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.DevActorRegistry;
import com.finsec.fuse.payment.PaymentFixture;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import static org.junit.jupiter.api.Assertions.*;

/** Real loopback HTTP server plus ephemeral PostgreSQL; no mocked routing or authorization. */
@SpringBootTest(classes=FuseApplication.class,webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
class PublicQueryContractIT extends PaymentFixture {
    @Value("${local.server.port}") int port;
    @Autowired DevActorRegistry registry;
    private final HttpClient client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private String token(String role,String... customers) {
        String token=DevActorRegistry.generateToken();
        issueToken(token,new Actor("query-"+UUID.randomUUID(),role,Set.of(customers)));return token;
    }
    private HttpResponse<String> get(String path,String token) throws Exception {
        var request=HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+path)).timeout(Duration.ofSeconds(10));
        if(token!=null)request.header("Authorization","Bearer "+token);
        return client.send(request.GET().build(),HttpResponse.BodyHandlers.ofString());
    }
    private HttpResponse<String> post(String path,String token,UUID action,String body) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+path)).timeout(Duration.ofSeconds(10))
            .header("Authorization","Bearer "+token).header("Idempotency-Key",action.toString()).header("Content-Type","application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
    }
    private String snapshot() {
        var result=new LinkedHashMap<String,Object>();
        for(String table:List.of("loan_application","workflow","agent_run","workflow_job","approval","mock_payment","risk_ledger","quarantine","action_request","audit_event"))
            result.put(table,db.query("SELECT * FROM "+table+" ORDER BY "+(table.equals("action_request")?"action_id":"id")));
        for(String table:List.of("demo_auth_registry","demo_token"))
            result.put(table,db.jdbc().queryForList("SELECT to_jsonb(t)::text FROM "+table+" t ORDER BY to_jsonb(t)::text",String.class));
        return json.write(result);
    }
    private void invalid(HttpResponse<String> response) {
        assertEquals(400,response.statusCode());var body=json.map(response.body());
        assertEquals(List.of("INVALID_REQUEST"),body.get("reasonCodes"));assertNull(body.get("state"));
        assertFalse(response.body().contains("pg_sleep"));assertFalse(response.body().contains("customerId="));
    }
    @Test void unknownListQueriesRejectBeforeReadsCanBroadenScopeOrMutateRows() throws Exception {
        start("customer-101");start("customer-102");String token=token("LOAN_REVIEWER","customer-102");String before=snapshot();
        for(String query:List.of("sort=created_at","customerId=customer-101","filter=all","State=KYC_PENDING","state=KYC_PENDING&unknown=x","%73ort=pg_sleep%282%29","state=KYC_PENDING&%63ustomerId=customer-101","page=0&%20size=10","page=0&%70age=1","%73tate=KYC_PENDING&state=PAID","%FF=1","%C0%AF=1","%E2%82=1","x".repeat(1024)+"=1"))
            invalid(get("/api/v1/workflows?"+query,token));
        assertEquals(before,snapshot());
        for(String query:List.of("state=KYC_PENDING&page=0&size=1","%73tate=KYC_PENDING&%70age=0&%73ize=1")) {
            var response=get("/api/v1/workflows?"+query,token);assertEquals(200,response.statusCode());
            var body=json.map(response.body());assertEquals(1,((Number)body.get("total")).intValue());
            var items=(List<?>)body.get("items");assertEquals(1,items.size());assertEquals("customer-102",((Map<?,?>)items.getFirst()).get("customerId"));
        }
        assertEquals(before,snapshot());
    }
    @Test void otherRoutesHaveNoQueryParametersAndAuthenticationStillRunsFirst() throws Exception {
        UUID workflow=start("customer-102");String token=token("LOAN_REVIEWER","customer-102");
        String service=token("KYC_SERVICE"),outOfScope=token("CUSTOMER","customer-101");String before=snapshot();
        for(String path:List.of("/api/v1/workflows/"+workflow,"/api/v1/workflows/"+workflow+"/trace","/api/v1/workflows/"+workflow+"/approval-preview",
                "/api/v1/incidents/"+UUID.randomUUID()+"/impact","/api/v1/experiments/"+UUID.randomUUID()))
            invalid(get(path+"?page=0",token));
        assertEquals(401,get("/api/v1/workflows?unknown=1",null).statusCode());
        assertEquals(403,get("/api/v1/workflows?unknown=1",service).statusCode());
        assertEquals(404,get("/api/v1/not-a-route?unknown=1",token).statusCode());
        assertEquals(403,get("/api/v1/workflows/"+workflow,outOfScope).statusCode());
        assertEquals(before,snapshot());
    }
    @Test void rejectedMutationQueryLeavesNoActionAndSameKeyCanBeUsedForValidRequest() throws Exception {
        String token=token("CUSTOMER","customer-102");UUID action=UUID.randomUUID();String before=snapshot();
        String body="{\"businessReference\":\"APP-DEMO-102-001\",\"customerId\":\"customer-102\",\"amountKrw\":1000000,\"payoutAccountId\":\"00000000-0000-4000-8000-000000000102\"}";
        invalid(post("/api/v1/workflows?state=KYC_PENDING",token,action,body));assertEquals(before,snapshot());
        var response=post("/api/v1/workflows",token,action,body);assertEquals(202,response.statusCode());
        assertEquals(1,count("workflow"));assertEquals(1,count("action_request"));assertEquals(0,count("mock_payment"));
        String after=snapshot();assertEquals(202,post("/api/v1/workflows",token,action,body).statusCode());assertEquals(after,snapshot());
    }
}
