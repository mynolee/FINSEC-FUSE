package com.finsec.fuse.auth;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.JsonConfiguration;
import com.finsec.fuse.testing.PostgresSupport;
import java.net.URI;
import java.net.http.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import static org.junit.jupiter.api.Assertions.*;

/** Two real application JVMs reuse one synthetic ledger without restart provisioning. */
class DemoTokenProcessRestartIT {
    private static final String REVIEWER="a".repeat(64),SERVICE="b".repeat(64),REVOKED="c".repeat(64),EXPIRING="d".repeat(64);
    private static final Set<String> BROAD=Set.of("customer-101","customer-102","customer-103","customer-104");
    private final Json json=new Json(new JsonConfiguration().jsonMapper());
    private final HttpClient client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    @TempDir Path work;
    @Test void expiryRevocationNarrowingAndOriginalTimesSurviveARealRestartAndSigningKeyChange()throws Exception {
        Files.setPosixFilePermissions(work,PosixFilePermissions.fromString("rwx------"));
        String schema="restart_auth_"+UUID.randomUUID().toString().replace("-","");String base=PostgresSupport.url();
        JdbcTemplate root=new JdbcTemplate(new DriverManagerDataSource(base,"postgres",""));root.execute("CREATE SCHEMA "+schema);
        String url=base+(base.contains("?")?"&":"?")+"currentSchema="+schema;
        var source=new DriverManagerDataSource(url,"postgres","");var jdbc=new JdbcTemplate(source);Process first=null,second=null;
        try {
            Flyway.configure().dataSource(source).schemas(schema).defaultSchema(schema).locations("classpath:db/migration").load().migrate();
            try(Connection c=source.getConnection()) {DemoTokenAdministration.initialize(c,List.of(binding(REVIEWER,new Actor("staff-01","LOAN_REVIEWER",BROAD)),binding(SERVICE,new Actor("kyc-service","KYC_SERVICE",Set.of())),binding(REVOKED,new Actor("revoked-reviewer","LOAN_REVIEWER",BROAD))));}
            first=launch(url,"first","first-key","2026-10-09T04:00:00Z");int firstPort=port(first,"first");
            assertEquals(200,get(firstPort,REVIEWER,"/api/v1/workflows").statusCode());
            var started=post(firstPort,REVIEWER,"{\"businessReference\":\"APP-DEMO-102-001\",\"customerId\":\"customer-102\",\"amountKrw\":1000000,\"payoutAccountId\":\"00000000-0000-4000-8000-000000000102\"}");
            assertEquals(202,started.statusCode());String workflow=(String)json.map(started.body()).get("workflowId");
            try(Connection c=source.getConnection()) {
                DemoTokenAdministration.revokeFingerprint(c,DevActorRegistry.fingerprint(REVOKED));
                DemoTokenAdministration.updateScope(c,"staff-01",Set.of("customer-101"));
                // Historical fixture insertion establishes a near expiry without changing immutable rows.
                try(PreparedStatement p=c.prepareStatement("INSERT INTO demo_token(fingerprint,registry_id,actor_id,role,initial_scope,current_scope,issued_at,expires_at,security_policy,issuance_ttl_seconds,status,revision) SELECT ?,registry_id,'expiring-reviewer','LOAN_REVIEWER',ARRAY['customer-101'],ARRAY['customer-101'],statement_timestamp()-interval '7195 seconds',statement_timestamp()+interval '5 seconds','FUSE-SECURITY-1',7200,'ACTIVE',0 FROM demo_auth_registry")) {
                    p.setBytes(1,HexFormat.of().parseHex(DevActorRegistry.fingerprint(EXPIRING)));p.executeUpdate();
                }
            }
            var authority=auth(jdbc);
            assertEquals(200,get(firstPort,EXPIRING,"/api/v1/workflows").statusCode());
            assertDeniedWithoutChanges(jdbc,firstPort,REVOKED,"/api/v1/workflows",401);
            assertDeniedWithoutChanges(jdbc,firstPort,REVIEWER,"/api/v1/workflows/"+workflow,403);
            assertEquals(authority,auth(jdbc));first.destroyForcibly();assertTrue(first.waitFor(15,TimeUnit.SECONDS));
            long expiryWait=System.nanoTime()+Duration.ofSeconds(15).toNanos();
            while(!Boolean.TRUE.equals(jdbc.queryForObject("SELECT clock_timestamp()>=expires_at FROM demo_token WHERE fingerprint=decode(?, 'hex')",Boolean.class,DevActorRegistry.fingerprint(EXPIRING)))) {
                assertTrue(System.nanoTime()<expiryWait);Thread.sleep(25);
            }
            // No fixture reset/issue here; workflow time and signing key change independently of token time.
            second=launch(url,"second","second-key","2026-10-10T04:00:00Z");int secondPort=port(second,"second");
            assertEquals(authority,auth(jdbc),"Every auth column, including original timestamps, must survive the distinct JVM");
            assertEquals(200,get(secondPort,REVIEWER,"/api/v1/workflows").statusCode());
            assertDeniedWithoutChanges(jdbc,secondPort,EXPIRING,"/api/v1/workflows",401);
            assertDeniedWithoutChanges(jdbc,secondPort,REVOKED,"/api/v1/workflows",401);
            assertDeniedWithoutChanges(jdbc,secondPort,REVIEWER,"/api/v1/workflows/"+workflow,403);
            assertDeniedWithoutChanges(jdbc,secondPort,SERVICE,"/api/v1/workflows",403);
            assertEquals(authority,auth(jdbc));
        } finally {
            for(Process child:new Process[]{first,second})if(child!=null&&child.isAlive()){child.destroyForcibly();child.waitFor(15,TimeUnit.SECONDS);}
            root.execute("DROP SCHEMA "+schema+" CASCADE");
        }
    }
    private DemoTokenStore.Binding binding(String token,Actor actor){return new DemoTokenStore.Binding(DevActorRegistry.fingerprint(token),actor);}
    private Process launch(String url,String phase,String keyId,String workflowTime)throws Exception {
        Properties config=new Properties();config.setProperty("database",url);config.setProperty("reviewer",REVIEWER);config.setProperty("service",SERVICE);config.setProperty("keyId",keyId);config.setProperty("workflowTime",workflowTime);
        config.setProperty("portFile",work.resolve(phase+".port").toString());config.setProperty("stopFile",work.resolve(phase+".stop").toString());
        Path file=Files.createFile(work.resolve(phase+".properties"),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try(var output=Files.newOutputStream(file)){config.store(output,"Synthetic owned process fixture");}
        String executable=Path.of(System.getProperty("java.home"),"bin","java").toString();
        var builder=new ProcessBuilder(executable,"-cp",System.getProperty("java.class.path"),DemoTokenRestartServer.class.getName(),file.toString());
        builder.environment().keySet().removeIf(name->name.startsWith("FUSE_")||name.startsWith("SPRING_")||name.endsWith("_API_KEY")
            ||name.startsWith("OPENAI_")||name.startsWith("ANTHROPIC_")||Set.of("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","PORT").contains(name));
        builder.redirectErrorStream(true);builder.redirectOutput(work.resolve(phase+".log").toFile());return builder.start();
    }
    private int port(Process process,String phase)throws Exception {
        Path port=work.resolve(phase+".port");long deadline=System.nanoTime()+Duration.ofSeconds(75).toNanos();
        while(!Files.exists(port)){assertTrue(process.isAlive(),"Child startup failed; inspect its private test log");assertTrue(System.nanoTime()<deadline,"Child startup timed out");Thread.sleep(25);}
        return Integer.parseInt(Files.readString(port));
    }
    private HttpResponse<String> get(int port,String token,String path)throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+path)).timeout(Duration.ofSeconds(10)).header("Authorization","Bearer "+token).GET().build(),HttpResponse.BodyHandlers.ofString());
    }
    private HttpResponse<String> post(int port,String token,String body)throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+"/api/v1/workflows")).timeout(Duration.ofSeconds(10)).header("Authorization","Bearer "+token).header("Idempotency-Key",UUID.randomUUID().toString()).header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
    }
    private void assertDeniedWithoutChanges(JdbcTemplate jdbc,int port,String token,String path,int status)throws Exception {
        var before=allRows(jdbc);assertEquals(status,get(port,token,path).statusCode());assertEquals(before,allRows(jdbc));
    }
    private Map<String,List<String>> auth(JdbcTemplate jdbc) {
        return Map.of("registry",jdbc.queryForList("SELECT to_jsonb(t)::text FROM demo_auth_registry t ORDER BY id",String.class),"tokens",jdbc.queryForList("SELECT to_jsonb(t)::text FROM demo_token t ORDER BY fingerprint",String.class));
    }
    private Map<String,List<String>> allRows(JdbcTemplate jdbc) {
        Map<String,List<String>> rows=new TreeMap<>();
        for(String table:jdbc.queryForList("SELECT tablename FROM pg_tables WHERE schemaname=current_schema() ORDER BY tablename",String.class))
            rows.put(table,jdbc.queryForList("SELECT to_jsonb(t)::text FROM \""+table.replace("\"","\"\"")+"\" t ORDER BY to_jsonb(t)::text",String.class));
        return rows;
    }
}
