package com.finsec.fuse.http;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.SecurityPolicy;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.*;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.util.Timeout;

/** Operator-selected fixed origin; no request/response value can choose a destination. */
public final class InternalKycHttpClient implements AutoCloseable {
    private final URI origin;
    private final SecurityPolicy policy;
    private final CloseableHttpClient client;
    private final ThreadPoolExecutor calls;
    public record Result(int status, byte[] body) {}
    public static final class InvalidOutput extends IOException {}
    @FunctionalInterface public interface Resolver { InetAddress[] resolve(String host) throws UnknownHostException; }

    public InternalKycHttpClient(String baseUrl, SecurityPolicy policy) {
        this(baseUrl, policy, InetAddress::getAllByName);
    }
    // Resolver injection is exclusively for isolated no-network contract tests.
    public InternalKycHttpClient(String baseUrl, SecurityPolicy policy, Resolver resolver) {
        this.policy=policy;
        origin=URI.create(baseUrl);
        if(origin.getHost()==null || origin.getUserInfo()!=null || origin.getQuery()!=null || origin.getFragment()!=null ||
           !(origin.getPath().isEmpty() || origin.getPath().equals("/")) ||
           !Set.of("http","https").contains(origin.getScheme()) || origin.getPort()==0 || origin.getPort()>65535)
            throw new IllegalArgumentException("Invalid internal KYC endpoint");
        String host=origin.getHost();
        boolean loopback=Set.of("localhost","127.0.0.1","[::1]","::1").contains(host);
        boolean isolated=host.equals("agent") && origin.getPort()==8001;
        if(!origin.getScheme().equals("https") && !loopback && !isolated)
            throw new IllegalArgumentException("Remote internal KYC endpoint requires verified TLS");
        final InetAddress[] pinned;
        try {
            pinned=resolver.resolve(host).clone();
            if(pinned.length==0)throw new UnknownHostException();
            for(var address:pinned) {
                boolean permitted=loopback ? address.isLoopbackAddress() : isolated ?
                    address.isSiteLocalAddress() && !address.isLinkLocalAddress() : publicAddress(address);
                if(!permitted)throw new UnknownHostException();
            }
        } catch(UnknownHostException invalid) {throw new IllegalArgumentException("Internal KYC destination unavailable or disallowed");}
        var dns=new DnsResolver() {
            public InetAddress[] resolve(String requested) throws UnknownHostException {
                if(!host.equals(requested))throw new UnknownHostException("Unregistered destination");
                return pinned.clone();
            }
            public String resolveCanonicalHostname(String requested) throws UnknownHostException {
                if(!host.equals(requested))throw new UnknownHostException("Unregistered destination");
                return host;
            }
        };
        var manager=PoolingHttpClientConnectionManagerBuilder.create().setDnsResolver(dns)
            .setMaxConnTotal(policy.modelConcurrency()).setMaxConnPerRoute(policy.modelConcurrency())
            .setDefaultConnectionConfig(ConnectionConfig.custom().setConnectTimeout(Timeout.ofSeconds(2))
                .setSocketTimeout(Timeout.ofSeconds(30)).build()).build();
        client=HttpClients.custom().setConnectionManager(manager).disableRedirectHandling().disableAutomaticRetries()
            .disableCookieManagement().disableContentCompression()
            // No system proxy properties; TLS strategy and hostname verification remain library defaults.
            .setDefaultRequestConfig(RequestConfig.custom().setRedirectsEnabled(false)
                .setConnectionRequestTimeout(Timeout.ofSeconds(2)).setResponseTimeout(Timeout.ofSeconds(30))
                .setHardCancellationEnabled(true).build()).build();
        calls=new ThreadPoolExecutor(policy.modelConcurrency(),policy.modelConcurrency(),30,TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(policy.modelConcurrency()), runnable->{var t=new Thread(runnable,"kyc-http");t.setDaemon(true);return t;},
            new ThreadPoolExecutor.AbortPolicy());
        calls.allowCoreThreadTimeOut(true);
    }
    private static boolean publicAddress(InetAddress address) {
        if(address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress() ||
           address.isSiteLocalAddress() || address.isMulticastAddress())return false;
        byte[] bytes=address.getAddress();
        if(bytes.length==16) return (bytes[0]&0xe0)==0x20; // globally routed unicast only, excludes ULA/mapped forms
        int a=bytes[0]&255,b=bytes[1]&255;
        return a!=0 && a<224 && !(a==100 && b>=64 && b<=127) && !(a==192 && b==0) &&
            !(a==198 && (b==18 || b==19)) && !(a==192 && b==168);
    }
    public Result post(String path, String token, byte[] body) throws Exception {
        if(!Set.of("/internal/v1/kyc/evaluations","/internal/v1/kyc/captures").contains(path))
            throw new IllegalArgumentException("Unregistered internal path");
        if(body.length>policy.internalRequestMaxBytes())throw new IllegalArgumentException("Internal request exceeds limit");
        var request=new HttpPost(origin.resolve(path));
        request.setHeader("Content-Type","application/json");
        request.setHeader("X-Fuse-Service-Token",token);
        request.setEntity(new ByteArrayEntity(body,ContentType.APPLICATION_JSON));
        Future<Result> future=calls.submit(()->client.execute(request,response->{
            var bytes=new ByteArrayOutputStream();
            if(response.getEntity()!=null)try(var stream=response.getEntity().getContent()) {
                byte[] buffer=new byte[4096];int count;
                while((count=stream.read(buffer))!=-1) {
                    if((long)bytes.size()+count>policy.internalResponseMaxBytes()){request.cancel();throw new InvalidOutput();}
                    bytes.write(buffer,0,count);
                }
            }
            return new Result(response.getCode(),bytes.toByteArray());
        }));
        try{return future.get(30,TimeUnit.SECONDS);}
        catch(InterruptedException|TimeoutException failure){request.cancel();future.cancel(true);throw failure;}
    }
    public static String jsonText(byte[] body) {
        try{return java.nio.charset.StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(body)).toString();}
        catch(java.nio.charset.CharacterCodingException invalid){throw new IllegalArgumentException("Invalid response encoding");}
    }
    public static SecurityPolicy policy(Json json) {
        try(var source=InternalKycHttpClient.class.getResourceAsStream("/config/security_policy.json")) {
            if(source==null)throw new IllegalStateException("Missing security policy");
            return json.read(source.readNBytes(16385),SecurityPolicy.class);
        }catch(IOException invalid){throw new IllegalStateException("Invalid security policy");}
    }
    @Override public void close() throws IOException {calls.shutdownNow();client.close();}
}
