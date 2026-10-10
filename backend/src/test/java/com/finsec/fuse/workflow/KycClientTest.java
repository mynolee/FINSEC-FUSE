package com.finsec.fuse.workflow;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.JsonConfiguration;
import com.finsec.fuse.config.PrivateDocuments;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

class KycClientTest {
    private final Json json=new Json(new JsonConfiguration().jsonMapper());
    private KycContract.Input input() {
        var raw=new KycContract.Input(UUID.randomUUID(),UUID.randomUUID(),1,UUID.randomUUID(),"customer-102","FUSE-MVP-2",null,List.of(),List.of());
        return raw.withHash(json.hash(raw.unhashed()));
    }
    @Test void transportsOnlyTheBoundEvaluationDtoAndServiceToken() throws Exception {
        var input=input();var captured=new AtomicReference<String>();var token=new AtomicReference<String>();
        var response=new KycContract.Response(input.requestId(),input.workflowId(),1,input.runId(),input.inputSnapshotHash(),
                new KycContract.Proposal(KycContract.ProposalStatus.NEEDS_REVIEW,List.of(),"Synthetic test"),new KycContract.ModelMetadata("replay","KYC-PROMPT-1"));
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        try {
            server.createContext("/internal/v1/kyc/evaluations",exchange->{
                captured.set(new String(exchange.getRequestBody().readAllBytes(),StandardCharsets.UTF_8));
                token.set(exchange.getRequestHeaders().getFirst("X-Fuse-Service-Token"));
                byte[] bytes=json.bytes(response);exchange.sendResponseHeaders(200,bytes.length);exchange.getResponseBody().write(bytes);exchange.close();
            });server.start();
            var client=new KycClient(json,"http://127.0.0.1:"+server.getAddress().getPort(),"test-only-kyc-token-000000000000000000");
            assertTrue(client.evaluate(input).boundTo(input));
            assertEquals(json.write(input),captured.get());assertEquals("test-only-kyc-token-000000000000000000",token.get());
            assertFalse(captured.get().contains("test-only-kyc-token-000000000000000000"));assertFalse(captured.get().contains("approvalId"));
        } finally { server.stop(0); }
    }
    @Test void oversizedAndMalformedOutputAreErrorsNeverPolicyBlocks() throws Exception {
        for(String body:List.of("{"+" ".repeat(65536)+"}","{\"requestId\":null,\"requestId\":null}")) {
            var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
            try {
                server.createContext("/internal/v1/kyc/evaluations",exchange->{
                    exchange.getRequestBody().readAllBytes();byte[] bytes=body.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(200,bytes.length);exchange.getResponseBody().write(bytes);exchange.close();
                });server.start();
                var client=new KycClient(json,"http://127.0.0.1:"+server.getAddress().getPort(),"test-only-kyc-token-000000000000000000");
                assertEquals("MODEL_OUTPUT_INVALID",assertThrows(KycClient.KycFailure.class,()->client.evaluate(input())).reasonCode());
            } finally { server.stop(0); }
        }
    }
    @Test void liveRejectsPersistedReplayMarkerBeforeTransport() throws Exception {
        var captured=new AtomicReference<String>();var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/internal/v1/kyc/evaluations",exchange->{captured.set("called");exchange.close();});server.start();
        try {
            var raw=input();String text="FUSE_DOCUMENT_ID:seed-v1";
            var input=new KycContract.Input(raw.requestId(),raw.workflowId(),1,raw.runId(),raw.customerId(),raw.policyVersion(),null,List.of(),
                List.of(new KycContract.Document(UUID.randomUUID(),1,Json.sha256(text.getBytes(StandardCharsets.UTF_8)),text)));
            var client=new KycClient(json,"http://127.0.0.1:"+server.getAddress().getPort(),"test-only-kyc-token-000000000000000000","live");
            assertEquals(PrivateDocuments.UNAVAILABLE,assertThrows(KycClient.KycFailure.class,()->client.evaluate(input.withHash(json.hash(input.unhashed())))).reasonCode());
            assertNull(captured.get());
        }finally{server.stop(0);}
    }
    @Test void privateDocumentFailureFromMismatchedServiceModeIsPreserved() throws Exception {
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/internal/v1/kyc/evaluations",exchange->{
            exchange.getRequestBody().readAllBytes();byte[] bytes=json.bytes(Map.of("reasonCode",PrivateDocuments.UNAVAILABLE));
            exchange.sendResponseHeaders(503,bytes.length);exchange.getResponseBody().write(bytes);exchange.close();});server.start();
        try {
            var client=new KycClient(json,"http://127.0.0.1:"+server.getAddress().getPort(),"test-only-kyc-token-000000000000000000");
            assertEquals(PrivateDocuments.UNAVAILABLE,assertThrows(KycClient.KycFailure.class,()->client.evaluate(input())).reasonCode());
        }finally{server.stop(0);}
    }
}
