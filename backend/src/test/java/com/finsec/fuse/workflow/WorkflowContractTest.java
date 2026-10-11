package com.finsec.fuse.workflow;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.JsonConfiguration;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class WorkflowContractTest {
    private final Json json=new Json(new JsonConfiguration().jsonMapper());
    @Test void loanRuleRemainsDeterministicAndMockOnly() {
        assertTrue(LoanCalculation.recommendsApproval(3_000_000,2_000_000,1_000_000,true));
        assertFalse(LoanCalculation.recommendsApproval(2_000_000,500_000,1_000_000,true));
        assertFalse(LoanCalculation.recommendsApproval(0,2_000_000,1_000_000,true));
        assertFalse(LoanCalculation.recommendsApproval(3_000_000,2_000_000,1_000_000,false));
        assertFalse(LoanCalculation.recommendsApproval(3_000_000,2_000_000,0,true));
    }
    @Test void canonicalInputExcludesItsOwnHashAndUsesFixedOrder() {
        var input=new KycContract.Input(UUID.randomUUID(),UUID.randomUUID(),1,UUID.randomUUID(),"customer-102","FUSE-MVP-2",null,List.of(),List.of());
        assertEquals(List.of("requestId","workflowId","generation","runId","customerId","policyVersion","evidenceFacts","documents"),new ArrayList<>(input.unhashed().keySet()));
        var hashed=input.withHash(json.hash(input.unhashed()));
        assertEquals(json.write(input.unhashed()),json.write(hashed.unhashed()));
        assertFalse(json.write(hashed.unhashed()).contains("inputSnapshotHash"));
    }
    @Test void completionRequiresCurrentTokenGenerationAndStrictlyFutureDeadline() {
        UUID token=UUID.randomUUID();Instant now=Instant.parse("2026-10-09T04:00:00Z");
        var job=new HashMap<String,Object>(Map.of("state","RUNNING","lease_token",token,"generation",1,"lease_until",now.plusSeconds(1)));
        var workflow=Map.<String,Object>of("generation",1);
        assertTrue(JobTransactions.valid(job,workflow,token,now));
        assertFalse(JobTransactions.valid(job,workflow,UUID.randomUUID(),now));
        assertFalse(JobTransactions.valid(job,Map.of("generation",2),token,now));
        job.put("lease_until",now);assertFalse(JobTransactions.valid(job,workflow,token,now));
        job.put("lease_until",now.plusSeconds(1));job.put("state","FAILED");assertFalse(JobTransactions.valid(job,workflow,token,now));
    }
    @Test void responseBindingCannotMoveAnAnswerToAnotherRun() {
        var input=new KycContract.Input(UUID.randomUUID(),UUID.randomUUID(),1,UUID.randomUUID(),"customer-102","FUSE-MVP-2","a".repeat(64),List.of(),List.of());
        var proposal=new KycContract.Proposal(KycContract.ProposalStatus.VERIFIED,List.of(),"Synthetic test");
        var metadata=new KycContract.ModelMetadata("replay","KYC-PROMPT-1");
        assertTrue(new KycContract.Response(input.requestId(),input.workflowId(),1,input.runId(),input.inputSnapshotHash(),proposal,metadata).boundTo(input));
        assertFalse(new KycContract.Response(input.requestId(),input.workflowId(),1,UUID.randomUUID(),input.inputSnapshotHash(),proposal,metadata).boundTo(input));
        assertThrows(IllegalArgumentException.class,()->new KycContract.Proposal(KycContract.ProposalStatus.VERIFIED,Collections.nCopies(11,UUID.randomUUID()),"too many"));
        assertThrows(IllegalArgumentException.class,()->new KycContract.Proposal(KycContract.ProposalStatus.VERIFIED,List.of(),"x".repeat(2001)));
    }
    @Test void actualHttpReaderRejectsOversizedChunkedBodyBeforeEofAndRecovers() throws Exception {
        var server=com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1",0),0);
        var release=new java.util.concurrent.CountDownLatch(1);
        var count=new java.util.concurrent.atomic.AtomicInteger();
        server.createContext("/internal/v1/kyc/evaluations",exchange->{
            exchange.getRequestBody().readAllBytes();
            if(count.incrementAndGet()==1) {
                exchange.sendResponseHeaders(200,0);
                try {
                    exchange.getResponseBody().write(new byte[65537]);exchange.getResponseBody().flush();
                    // The response has not ended: rejection must not drain until EOF.
                    release.await(5,java.util.concurrent.TimeUnit.SECONDS);
                }catch(java.io.IOException expectedCancellation) { }
                catch(InterruptedException interrupted){Thread.currentThread().interrupt();}
                finally{exchange.close();}
            }else{
                byte[] valid=new byte[65536];exchange.sendResponseHeaders(200,valid.length);
                exchange.getResponseBody().write(valid);exchange.close();
            }
        });server.start();
        try(var client=new com.finsec.fuse.http.InternalKycHttpClient("http://127.0.0.1:"+server.getAddress().getPort(),
                com.finsec.fuse.http.InternalKycHttpClient.policy(json))) {
            assertTimeoutPreemptively(java.time.Duration.ofSeconds(2),()->{
                var failure=assertThrows(java.util.concurrent.ExecutionException.class,()->client.post(
                    "/internal/v1/kyc/evaluations","synthetic-only-token",new byte[0]));
                assertInstanceOf(com.finsec.fuse.http.InternalKycHttpClient.InvalidOutput.class,failure.getCause());
            });
            release.countDown();
            assertEquals(65536,client.post("/internal/v1/kyc/evaluations","synthetic-only-token",new byte[0]).body().length);
        }finally{release.countDown();server.stop(0);}
    }
}
