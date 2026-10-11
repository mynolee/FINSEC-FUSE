package com.finsec.fuse.experiments;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.JsonConfiguration;
import com.finsec.fuse.config.PrivateDocuments;
import com.finsec.fuse.workflow.KycContract;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Only loopback fake service requests; synthetic test token, never provider credentials. */
class ExperimentCaptureClientTest {
    private final Json json=new Json(new JsonConfiguration().jsonMapper());
    private KycContract.Input input(){var i=new KycContract.Input(UUID.randomUUID(),UUID.randomUUID(),1,UUID.randomUUID(),"customer-101","FUSE-MVP-2",null,List.of(),List.of());return i.withHash(json.hash(i.unhashed()));}
    private ExperimentModelCapture capture(KycContract.Input i){
        var proposal=new KycContract.Proposal(KycContract.ProposalStatus.NOT_VERIFIED,List.of(),"독립 증거 없음");
        return new ExperimentModelCapture(new KycContract.Response(i.requestId(),i.workflowId(),1,i.runId(),i.inputSnapshotHash(),proposal,new KycContract.ModelMetadata("actual-provider-model","KYC-PROMPT-1")),"LIVE","e".repeat(64),json.hash(ExperimentRegistry.sorted(json.map(json.write(proposal)))));
    }
    @Test void exactSingleInternalCallPreservesUtf8HashesAndBoundResponse() throws Exception {
        var input=input();var expected=capture(input);var calls=new AtomicInteger();
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/internal/v1/kyc/captures",exchange->{
            calls.incrementAndGet();assertEquals("test-only-service-00000000000000000",exchange.getRequestHeaders().getFirst("X-Fuse-Service-Token"));
            assertEquals(input,json.read(exchange.getRequestBody().readAllBytes(),KycContract.Input.class));
            byte[] body=json.bytes(expected);exchange.sendResponseHeaders(200,body.length);exchange.getResponseBody().write(body);exchange.close();
        });server.start();
        try {var actual=new ExperimentCaptureClient(json,"http://127.0.0.1:"+server.getAddress().getPort(),"test-only-service-00000000000000000").capture(input);
            assertEquals(expected,actual);assertEquals(1,calls.get());
        }finally{server.stop(0);}
    }
    @Test void invalidModeBindingAndOversizeAreErrorsWithoutRetries() throws Exception {
        var input=input();
        for(String body:List.of(json.write(capture(input)).replace("\"LIVE\"","\"REPLAY\""),json.write(capture(input())),"x".repeat(65_537)))
            assertFailure(input,200,body,"MODEL_OUTPUT_INVALID");
    }
    @Test void providerFailuresAndRedirectsNeverFollowAnotherOrigin() throws Exception {
        assertFailure(input(),503,"{\"reasonCode\":\"LIVE_NOT_AVAILABLE\"}","LIVE_NOT_AVAILABLE");
        assertFailure(input(),502,"{\"reasonCode\":\"MODEL_OUTPUT_INVALID\"}","MODEL_OUTPUT_INVALID");
        assertFailure(input(),302,"redirect","DEPENDENCY_UNAVAILABLE");
        assertFailure(input(),503,"{\"reasonCode\":\"PRIVATE_DOCUMENTS_UNAVAILABLE\"}",PrivateDocuments.UNAVAILABLE);
    }
    @Test void unresolvedReplayMarkerNeverCrossesLiveCaptureBoundary() throws Exception {
        var calls=new AtomicInteger();var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/internal/v1/kyc/captures",exchange->{calls.incrementAndGet();exchange.close();});server.start();
        try {
            var original=input();String text="FUSE_DOCUMENT_ID:seed-v1";
            var input=new KycContract.Input(original.requestId(),original.workflowId(),1,original.runId(),original.customerId(),original.policyVersion(),null,List.of(),
                List.of(new KycContract.Document(UUID.randomUUID(),1,Json.sha256(text.getBytes(StandardCharsets.UTF_8)),text)));
            var client=new ExperimentCaptureClient(json,"http://127.0.0.1:"+server.getAddress().getPort(),"test-only-service-00000000000000000");
            assertEquals(PrivateDocuments.UNAVAILABLE,assertThrows(ExperimentCaptureClient.CaptureFailure.class,()->client.capture(input.withHash(json.hash(input.unhashed())))).reason());
            assertEquals(0,calls.get());
        }finally{server.stop(0);}
    }
    @Test void endpointAndEmptyTokenAreFailClosed(){
        for(String url:List.of("file:///tmp/value","https://user:secret@example.invalid","https://example.invalid?token=secret"))
            assertThrows(IllegalArgumentException.class,()->new ExperimentCaptureClient(json,url,"test"));
        assertThrows(ExperimentCaptureClient.CaptureFailure.class,()->new ExperimentCaptureClient(json,"http://127.0.0.1:1","").capture(input()));
    }
    private void assertFailure(KycContract.Input input,int status,String content,String reason) throws Exception {
        var calls=new AtomicInteger();var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/internal/v1/kyc/captures",exchange->{calls.incrementAndGet();exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().add("Location","http://127.0.0.1:1/must-not-follow");
            byte[] body=content.getBytes(StandardCharsets.UTF_8);exchange.sendResponseHeaders(status,body.length);exchange.getResponseBody().write(body);exchange.close();});server.start();
        try {var error=assertThrows(ExperimentCaptureClient.CaptureFailure.class,()->new ExperimentCaptureClient(json,"http://127.0.0.1:"+server.getAddress().getPort(),"test-only-service-00000000000000000").capture(input));assertEquals(reason,error.reason());assertEquals(1,calls.get());}
        finally{server.stop(0);}
    }
}
