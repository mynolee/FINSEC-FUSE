package com.finsec.fuse.http;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.JsonConfiguration;
import com.finsec.fuse.config.SecurityPolicy;
import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class InternalKycHttpClientTest {
    private final SecurityPolicy policy=InternalKycHttpClient.policy(new Json(new JsonConfiguration().jsonMapper()));
    @Test void resolvesOnlyOnceAndUsesPinnedConnectionWithoutRedirectOrProxy() throws Exception {
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        var lookups=new AtomicInteger();var originCalls=new AtomicInteger();var forbiddenCalls=new AtomicInteger();
        server.createContext("/internal/v1/kyc/evaluations",exchange->{originCalls.incrementAndGet();exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().add("Location","/forbidden");exchange.sendResponseHeaders(307,-1);exchange.close();});
        server.createContext("/forbidden",exchange->{forbiddenCalls.incrementAndGet();exchange.close();});server.start();
        String old=System.getProperty("http.proxyHost");System.setProperty("http.proxyHost","invalid-proxy.test");
        try(var client=new InternalKycHttpClient("http://localhost:"+server.getAddress().getPort(),policy,host->{
            assertEquals("localhost",host);assertEquals(1,lookups.incrementAndGet(),"must not re-resolve after validation");
            return new InetAddress[]{InetAddress.getByAddress(new byte[]{127,0,0,1})};})) {
            for(int n=0;n<2;n++)assertEquals(307,client.post("/internal/v1/kyc/evaluations","synthetic-token","{}".getBytes()).status());
            assertEquals(1,lookups.get());assertEquals(2,originCalls.get());assertEquals(0,forbiddenCalls.get());
        }finally{server.stop(0);if(old==null)System.clearProperty("http.proxyHost");else System.setProperty("http.proxyHost",old);}
    }
    @Test void narrowPrivateExceptionsRejectMetadataAndConfigurationOverridesWithoutNetwork() throws Exception {
        for(String url:List.of("file:///tmp/fake","http://127.1:8001","http://localhost:8001/other","http://agent:8002",
                "http://anything.test:8001","https://user:pass@anything.test","https://anything.test?q=1","https://anything.test#x"))
            assertThrows(IllegalArgumentException.class,()->new InternalKycHttpClient(url,policy,host->{fail("invalid configuration must not resolve");return null;}));
        for(byte[] ip:List.of(new byte[]{127,0,0,1},new byte[]{10,0,0,1},new byte[]{(byte)169,(byte)254,(byte)169,(byte)254},new byte[]{100,64,0,1}))
            assertThrows(IllegalArgumentException.class,()->new InternalKycHttpClient("https://model.test",policy,host->new InetAddress[]{InetAddress.getByAddress(ip)}));
        assertThrows(IllegalArgumentException.class,()->new InternalKycHttpClient("http://localhost:8001",policy,
            host->new InetAddress[]{InetAddress.getByAddress(new byte[]{10,0,0,1})}));
        try(var client=new InternalKycHttpClient("http://agent:8001",policy,
            host->new InetAddress[]{InetAddress.getByAddress(new byte[]{10,0,0,2})})) {
            // Construction validates the exact isolated alias; this test never connects.
            assertNotNull(client);
        }
    }
    @Test void rejectsOversizedBodyAndUnregisteredPathBeforeConnection() throws Exception {
        try(var client=new InternalKycHttpClient("http://127.0.0.1:1",policy)) {
            assertThrows(IllegalArgumentException.class,()->client.post("/not-registered","test",new byte[0]));
            assertThrows(IllegalArgumentException.class,()->client.post("/internal/v1/kyc/evaluations","test",new byte[262145]));
        }
    }
}
