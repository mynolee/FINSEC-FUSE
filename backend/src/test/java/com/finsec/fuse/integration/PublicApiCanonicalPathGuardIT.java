package com.finsec.fuse.integration;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.AdmissionLimiter;
import com.finsec.fuse.auth.DevActorRegistry;
import com.finsec.fuse.config.SecurityPolicy;
import com.finsec.fuse.experiments.ExperimentCaptureGateway;
import com.finsec.fuse.experiments.ExperimentRequest;
import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.workflow.KycGateway;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.apache.catalina.util.ServerInfo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringBootVersion;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.core.MethodParameter;
import org.springframework.core.Ordered;
import org.springframework.core.SpringVersion;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdviceAdapter;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Real loopback Tomcat, root/default servlet mapping only. No connector policy override.
 * A 401 alone is not evidence: the passive observer must see no application body reads,
 * handler entry or MVC conversion. Container buffering/swallowing is not measured.
 * This regression is authored for the isolated CI harness; it is not an ingress proof.
 */
@SpringBootTest(classes=FuseApplication.class,webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties="server.address=127.0.0.1")
@Import(PublicApiCanonicalPathGuardIT.ProbeConfiguration.class)
@DirtiesContext(classMode=DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class PublicApiCanonicalPathGuardIT extends PaymentFixture {
    private static final String CANONICAL="/api/v1/experiments";
    private static final List<String> ALIASES=List.of("/%61pi/v1/experiments","/api;v=1/v1/experiments");
    private static final String SMALL="{\"fixtureSetId\":\"synthetic\",\"caseIds\":[\"c\"],"
        +"\"mode\":\"PAIRED\",\"modelMode\":\"REPLAY\",\"repeatCount\":1}";
    private static final String OVERSIZED=SMALL.replace("[\"c\"]","["+"\"c\",".repeat(18000)+"\"c\"]");
    private static final String PROBE_HEADER="X-Path-Probe";
    @Value("${local.server.port}") int port;
    @Autowired Probe probe;
    @Autowired ServletContext servletContext;
    private HttpClient client;

    static class Observation {
        final String raw,servlet,pathInfo,context,mapping,remote,transfer;
        final long contentLength;
        final AtomicLong bytes=new AtomicLong();
        final AtomicInteger handlers=new AtomicInteger(),conversions=new AtomicInteger();
        final CountDownLatch finished=new CountDownLatch(1);
        Observation(HttpServletRequest request) {
            raw=request.getRequestURI();servlet=request.getServletPath();pathInfo=request.getPathInfo();
            context=request.getContextPath();mapping=request.getHttpServletMapping().getPattern();
            remote=request.getRemoteAddr();transfer=request.getHeader("Transfer-Encoding");
            contentLength=request.getContentLengthLong();
        }
    }
    static class Probe {
        final Map<String,Observation> observations=new ConcurrentHashMap<>();
        final ThreadLocal<Observation> current=new ThreadLocal<>();
        final AtomicInteger kyc=new AtomicInteger(),experiment=new AtomicInteger();
    }
    static class CountingInput extends ServletInputStream {
        private final ServletInputStream delegate;
        private final Observation observation;
        CountingInput(ServletInputStream delegate,Observation observation){this.delegate=delegate;this.observation=observation;}
        public int read() throws IOException {int n=delegate.read();if(n>=0)observation.bytes.incrementAndGet();return n;}
        public int read(byte[] buffer,int offset,int length) throws IOException {
            int n=delegate.read(buffer,offset,length);if(n>0)observation.bytes.addAndGet(n);return n;
        }
        public boolean isFinished(){return delegate.isFinished();}
        public boolean isReady(){return delegate.isReady();}
        public void setReadListener(ReadListener listener){delegate.setReadListener(listener);}
        public void close() throws IOException {delegate.close();}
    }
    static class CountingRequest extends HttpServletRequestWrapper {
        private final Observation observation;
        private ServletInputStream input;
        CountingRequest(HttpServletRequest request,Observation observation){super(request);this.observation=observation;}
        public ServletInputStream getInputStream() throws IOException {
            if(input==null)input=new CountingInput(super.getInputStream(),observation);return input;
        }
        public BufferedReader getReader() throws IOException {
            return new BufferedReader(new InputStreamReader(getInputStream(),StandardCharsets.UTF_8));
        }
    }
    static class PassiveFilter implements Filter {
        private final Probe probe;
        PassiveFilter(Probe probe){this.probe=probe;}
        public void doFilter(ServletRequest request,ServletResponse response,FilterChain chain) throws IOException,ServletException {
            var http=(HttpServletRequest)request;
            String id=http.getHeader(PROBE_HEADER);
            if(id==null){chain.doFilter(request,response);return;}
            var observation=new Observation(http);probe.observations.put(id,observation);probe.current.set(observation);
            try {chain.doFilter(new CountingRequest(http,observation),response);}
            finally {probe.current.remove();observation.finished.countDown();}
        }
    }
    // Register last but prepend the mapping, ahead of application filters even at MIN_VALUE.
    static class ProbeInitializer implements ServletContextInitializer,Ordered {
        private final Probe probe;
        ProbeInitializer(Probe probe){this.probe=probe;}
        public int getOrder(){return Ordered.LOWEST_PRECEDENCE;}
        public void onStartup(ServletContext context) {
            var registration=context.addFilter("canonicalPathPassiveProbe",new PassiveFilter(probe));
            assertNotNull(registration);
            registration.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST),false,"/*");
        }
    }
    @ControllerAdvice
    @TestConfiguration(proxyBeanMethods=false)
    static class ConversionProbe extends RequestBodyAdviceAdapter {
        private final Probe probe;
        ConversionProbe(Probe probe){this.probe=probe;}
        public boolean supports(MethodParameter parameter,Type targetType,Class<? extends HttpMessageConverter<?>> converter) {
            return parameter.getParameterType()==ExperimentRequest.class;
        }
        public HttpInputMessage beforeBodyRead(HttpInputMessage input,MethodParameter parameter,Type type,
                Class<? extends HttpMessageConverter<?>> converter) {
            var observation=probe.current.get();if(observation!=null)observation.conversions.incrementAndGet();return input;
        }
    }
    static class HandlerProbe implements HandlerInterceptor {
        private final Probe probe;
        HandlerProbe(Probe probe){this.probe=probe;}
        public boolean preHandle(HttpServletRequest request,HttpServletResponse response,Object handler) {
            var observation=probe.current.get();if(observation!=null)observation.handlers.incrementAndGet();return true;
        }
    }
    static class ProbeMvc implements WebMvcConfigurer {
        private final Probe probe;
        ProbeMvc(Probe probe){this.probe=probe;}
        public void addInterceptors(InterceptorRegistry registry){registry.addInterceptor(new HandlerProbe(probe));}
    }
    @TestConfiguration(proxyBeanMethods=false)
    static class ProbeConfiguration {
        @Bean Probe canonicalPathProbe(){return new Probe();}
        @Bean ProbeInitializer canonicalPathInitializer(Probe probe){return new ProbeInitializer(probe);}
        @Bean ConversionProbe canonicalPathConversion(Probe probe){return new ConversionProbe(probe);}
        @Bean ProbeMvc canonicalPathMvc(Probe probe){return new ProbeMvc(probe);}
        @Bean @Primary AdmissionLimiter canonicalPathLimiter(SecurityPolicy policy) {
            return new AdmissionLimiter(policy,Clock.fixed(Instant.parse("2026-10-09T04:00:00Z"),ZoneOffset.UTC));
        }
        @Bean @Primary KycGateway noPathKyc(Probe probe) {
            return input->{probe.kyc.incrementAndGet();throw new AssertionError("Unexpected KYC call");};
        }
        @Bean @Primary ExperimentCaptureGateway noPathExperiment(Probe probe) {
            return input->{probe.experiment.incrementAndGet();throw new AssertionError("Unexpected model capture");};
        }
    }
    private record State(String token,String readToken,Map<String,List<String>> before) {}
    private record Result(HttpResponse<String> response,Observation observation) {}

    @AfterEach void closeClient(){if(client!=null)client.close();}
    private State prepare() {
        assertEquals("4.1.1",SpringBootVersion.getVersion());assertEquals("7.0.9",SpringVersion.getVersion());
        assertEquals("Apache Tomcat/11.0.26",ServerInfo.getServerInfo());
        assertEquals("127.0.0.1",environment.getProperty("server.address"));
        assertFalse(environment.getProperty("fuse.worker-enabled",Boolean.class,true));
        assertTrue(List.of(environment.getActiveProfiles()).contains("test"));
        assertEquals("",servletContext.getContextPath());
        assertEquals(Set.of("/"),Set.copyOf(servletContext.getServletRegistration("dispatcherServlet").getMappings()));
        assertTrue(port>0);assertTrue(OVERSIZED.getBytes(StandardCharsets.UTF_8).length>65536);
        assertTrue(OVERSIZED.getBytes(StandardCharsets.UTF_8).length<80000);
        client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER)
            .version(HttpClient.Version.HTTP_1_1).build();
        start("customer-101"); // Non-vacuous committed workflow/jobs/receipt/audit state; no gateway invocation.
        String token=DevActorRegistry.generateToken();
        issueToken(token,new Actor("path-developer-"+UUID.randomUUID(),"DEVELOPER",Set.of("customer-101")));
        String readToken=DevActorRegistry.generateToken();
        issueToken(readToken,new Actor("path-reader-"+UUID.randomUUID(),"CUSTOMER",Set.of("customer-101")));
        var before=snapshot();
        for(String table:List.of("workflow","workflow_job","action_request","audit_event","demo_token"))
            assertFalse(before.get(table).isEmpty(),table);
        return new State(token,readToken,before);
    }
    private Result request(String path,String token,String body,boolean chunked,String... extraHeaders) throws Exception {
        String id=UUID.randomUUID().toString();URI uri=URI.create("http://127.0.0.1:"+port+path);
        assertEquals(path.split("\\?",2)[0],uri.getRawPath(),"Client must retain the exact raw target");
        var builder=HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(10)).header(PROBE_HEADER,id);
        if(token!=null)builder.header("Authorization","Bearer "+token);
        if(body==null)builder.GET();
        else {
            builder.header("Content-Type","application/json").header("Idempotency-Key",UUID.randomUUID().toString());
            var known=HttpRequest.BodyPublishers.ofString(body,StandardCharsets.UTF_8);
            // fromPublisher without a length yields finite HTTP/1.1 chunked framing.
            builder.POST(chunked?HttpRequest.BodyPublishers.fromPublisher(known):known);
        }
        for(int i=0;i<extraHeaders.length;i+=2)builder.header(extraHeaders[i],extraHeaders[i+1]);
        var response=client.send(builder.build(),HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        var observation=probe.observations.remove(id);assertNotNull(observation,"Passive filter must run");
        assertTrue(observation.finished.await(5,TimeUnit.SECONDS));
        assertEquals(uri.getRawPath(),observation.raw,"Actual server request URI must retain the alias");
        assertEquals("",observation.context);assertEquals("/",observation.mapping);
        assertEquals("127.0.0.1",observation.remote);
        if(ALIASES.contains(path))assertEquals(CANONICAL,observation.servlet,"Tomcat must map the alias to the protected path");
        if(body!=null) {
            assertEquals(chunked?-1:body.getBytes(StandardCharsets.UTF_8).length,observation.contentLength);
            if(chunked)assertEquals("chunked",observation.transfer);
            else assertNull(observation.transfer);
        }
        return new Result(response,observation);
    }
    private void rejected(Result result,int status,long bodyBytes) {
        assertEquals(status,result.response().statusCode());
        assertEquals("no-store",result.response().headers().firstValue("Cache-Control").orElseThrow());
        assertEquals("nosniff",result.response().headers().firstValue("X-Content-Type-Options").orElseThrow());
        assertEquals(bodyBytes,result.observation().bytes.get(),"Application bytes read before rejection");
        assertEquals(0,result.observation().handlers.get(),"No MVC handler entry before rejection");
        assertEquals(0,result.observation().conversions.get(),"No ExperimentRequest conversion before rejection");
    }
    private Map<String,List<String>> snapshot() {
        var read=new TransactionTemplate(Objects.requireNonNull(tx.getTransactionManager()));
        read.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        read.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);read.setReadOnly(true);
        return read.execute(status->{
            var rows=new LinkedHashMap<String,List<String>>();
            var tables=db.jdbc().queryForList("SELECT table_name FROM information_schema.tables "
                +"WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name",String.class);
            assertTrue(tables.containsAll(List.of("demo_auth_registry","demo_token","workflow","workflow_job",
                "action_request","experiment","experiment_case_result","experiment_arm_binding","mock_payment",
                "risk_ledger","audit_event")));
            for(String table:tables)rows.put(table,db.jdbc().queryForList("SELECT to_jsonb(t)::text FROM public.\""
                +table.replace("\"","\"\"")+"\" t ORDER BY to_jsonb(t)::text",String.class));
            return rows;
        });
    }
    private void unchanged(State state) {
        // Authentication SELECTs are permitted. This asserts no committed business/authority mutations, not zero SQL.
        assertTrue(state.before().equals(snapshot()),"All committed public-table rows must remain unchanged");
        assertEquals(0,probe.kyc.get());assertEquals(0,probe.experiment.get());
    }

    @Test @Timeout(180)
    void unauthenticatedCanonicalAndAliasesRejectBeforeAnyBodyParsing() throws Exception {
        var state=prepare();
        for(String path:List.of(CANONICAL,ALIASES.get(0),ALIASES.get(1)))
            for(boolean chunked:List.of(false,true))for(String body:List.of(SMALL,"{",OVERSIZED)) {
                rejected(request(path,null,body,chunked),401,0);unchanged(state);
            }
    }
    @Test @Timeout(180)
    void validBearerAliasesRemainOutsideRawAllowlistForBothFramings() throws Exception {
        var state=prepare();
        for(String path:ALIASES)for(boolean chunked:List.of(false,true))
            for(String body:List.of(SMALL,OVERSIZED)) {
                rejected(request(path,state.token(),body,chunked),404,0);unchanged(state);
            }
    }
    @Test @Timeout(180)
    void canonicalOversizedBodiesEnforceLengthAndStreamingBoundsBeforeMvc() throws Exception {
        var state=prepare();
        rejected(request(CANONICAL,state.token(),OVERSIZED,false),413,0);unchanged(state);
        rejected(request(CANONICAL,state.token(),OVERSIZED,true),413,65537);unchanged(state);
    }
    @Test @Timeout(180)
    void aliasAnonymousSaturationDoesNotBlockValidCanonicalCallerOnSameIp() throws Exception {
        var state=prepare();
        for(int i=0;i<30;i++)rejected(request(ALIASES.get(i%2),null,SMALL,false),401,0);
        rejected(request(ALIASES.get(0),null,SMALL,false),429,0);
        var valid=request("/api/v1/workflows?page=0&size=20",state.readToken(),null,false);
        assertEquals(200,valid.response().statusCode());assertEquals(1,valid.observation().handlers.get());
        assertEquals(0,valid.observation().bytes.get());assertEquals(0,valid.observation().conversions.get());
        rejected(request(ALIASES.get(1),null,SMALL,false),429,0);unchanged(state);
    }
    @Test @Timeout(180)
    void canonicalAndAliasHeaderChecksRemainAheadOfBodies() throws Exception {
        var state=prepare();
        for(String path:List.of(CANONICAL,ALIASES.get(0),ALIASES.get(1))) {
            rejected(request(path,state.token(),SMALL,false,"Authorization","Bearer "+state.token()),400,0);
            rejected(request(path,state.token(),SMALL,false,"Idempotency-Key",UUID.randomUUID().toString()),400,0);
            unchanged(state);
        }
        rejected(request(CANONICAL+"?role=DEVELOPER",state.token(),SMALL,false),400,0);
        rejected(request(CANONICAL,state.token(),SMALL,false,"Content-Encoding","gzip"),415,0);
        // Positive instrumentation control: safe unknown-field failure enters MVC conversion,
        // but cannot invoke the controller/business service or model capture.
        String unknownField=SMALL.substring(0,SMALL.length()-1)+",\"unexpected\":true}";
        var binding=request(CANONICAL,state.token(),unknownField,false);
        assertEquals(400,binding.response().statusCode());
        assertEquals(1,binding.observation().handlers.get());assertEquals(1,binding.observation().conversions.get());
        assertEquals(unknownField.getBytes(StandardCharsets.UTF_8).length,binding.observation().bytes.get());
        unchanged(state);
    }
}
