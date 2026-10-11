package com.finsec.fuse.auth;

import com.finsec.fuse.config.JsonConfiguration;
import com.finsec.fuse.testing.PostgresSupport;
import java.sql.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.env.MockEnvironment;
import static org.junit.jupiter.api.Assertions.*;

/** Real PostgreSQL gates; synthetic credentials and independently owned disposable schemas only. */
class JdbcDemoTokenStoreIT {
    private static final String TOKEN="a".repeat(64),OTHER="b".repeat(64),THIRD="c".repeat(64);
    private static final Actor ACTOR=new Actor("customer-101","CUSTOMER",Set.of("customer-101"));
    private DataSource source;private JdbcTemplate jdbc;private String schema;
    @BeforeEach void migrateOwnedSchema() {
        schema="auth_"+UUID.randomUUID().toString().replace("-","");
        new JdbcTemplate(base()).execute("CREATE SCHEMA "+schema);
        source=source(schema);jdbc=new JdbcTemplate(source);migrate(source,schema);
    }
    @AfterEach void removeOwnedSchema() {new JdbcTemplate(base()).execute("DROP SCHEMA "+schema+" CASCADE");}
    private static DataSource base(){return new DriverManagerDataSource(PostgresSupport.url(),"postgres","");}
    private static DataSource source(String schema) {
        String url=PostgresSupport.url();return new DriverManagerDataSource(url+(url.contains("?")?"&":"?")+"currentSchema="+schema,"postgres","");
    }
    private static void migrate(DataSource source,String schema) {
        Flyway.configure().dataSource(source).schemas(schema).defaultSchema(schema).locations("classpath:db/migration").load().migrate();
    }
    private DemoTokenStore.Binding binding(String token,Actor actor){return new DemoTokenStore.Binding(DevActorRegistry.fingerprint(token),actor);}
    private void initialize()throws Exception {try(Connection c=source.getConnection()){DemoTokenAdministration.initialize(c,List.of(binding(TOKEN,ACTOR)));}}
    private DevActorRegistry registry(String token)throws Exception {
        var env=new MockEnvironment().withProperty("FUSE_CUSTOMER_101_TOKEN",token);env.setActiveProfiles("test");
        var mapper=new JsonConfiguration().jsonMapper();return new DevActorRegistry(env,new JsonConfiguration().securityPolicy(mapper),new JdbcDemoTokenStore(jdbc));
    }
    private List<String> history(){return jdbc.queryForList("SELECT to_jsonb(t)::text FROM demo_token t ORDER BY fingerprint",String.class);}
    private void historical(String token,Instant issued)throws Exception {
        try(Connection c=source.getConnection()) {
            var scope=c.createArrayOf("text",new String[]{"customer-101"});
            try(PreparedStatement p=c.prepareStatement("INSERT INTO demo_token(fingerprint,registry_id,actor_id,role,initial_scope,current_scope,issued_at,expires_at,security_policy,issuance_ttl_seconds,status,revision) SELECT ?,registry_id,'customer-101','CUSTOMER',?,?,?,?,'FUSE-SECURITY-1',7200,'ACTIVE',0 FROM demo_auth_registry")) {
                p.setBytes(1,HexFormat.of().parseHex(DevActorRegistry.fingerprint(token)));p.setArray(2,scope);p.setArray(3,scope);p.setTimestamp(4,Timestamp.from(issued));p.setTimestamp(5,Timestamp.from(issued.plusSeconds(7200)));p.executeUpdate();
            } finally {scope.free();}
        }
    }
    @Test void constructionDoesNotInitializeAndMissingMarkerOrConfiguredRowFailsClosed()throws Exception {
        var registry=registry(TOKEN);assertEquals(0,jdbc.queryForObject("SELECT count(*) FROM demo_auth_registry",Integer.class));
        assertThrows(DemoTokenStore.Unavailable.class,registry::requireReady);assertThrows(DemoTokenStore.Unavailable.class,()->registry.resolve(TOKEN));
        assertEquals(List.of(),history());
        try(Connection c=source.getConnection()){DemoTokenAdministration.initialize(c,List.of());}
        assertThrows(DemoTokenStore.Unavailable.class,registry::requireReady);assertEquals(List.of(),history());
        try(Connection c=source.getConnection()){DemoTokenAdministration.issue(c,binding(TOKEN,ACTOR),Set.of());}
        assertNotNull(registry.resolve(TOKEN));
    }
    @Test void independentInstancesPreserveTimesRevocationAndExplicitScopeChanges()throws Exception {
        initialize();var first=registry(TOKEN);var second=registry(TOKEN);var original=history();
        for(int n=0;n<3;n++){assertNotNull(first.resolve(TOKEN));assertNotNull(second.resolve(TOKEN));assertEquals(original,history());}
        var initial=jdbc.queryForMap("SELECT issued_at,expires_at,array_to_json(initial_scope)::text AS initial_scope FROM demo_token");
        try(Connection c=source.getConnection()){assertEquals(1,DemoTokenAdministration.updateScope(c,ACTOR.actorId(),Set.of()));}
        assertEquals(Set.of(),first.resolve(TOKEN).customerIds());assertEquals(Set.of(),second.resolve(TOKEN).customerIds());
        try(Connection c=source.getConnection()){assertEquals(1,DemoTokenAdministration.revokeActor(c,ACTOR.actorId()));assertEquals(0,DemoTokenAdministration.revokeActor(c,ACTOR.actorId()));DemoTokenAdministration.updateScope(c,ACTOR.actorId(),Set.of("customer-102"));}
        assertNull(registry(TOKEN).resolve(TOKEN));
        var after=jdbc.queryForMap("SELECT issued_at,expires_at,array_to_json(initial_scope)::text AS initial_scope FROM demo_token");
        assertEquals(initial.get("issued_at"),after.get("issued_at"));assertEquals(initial.get("expires_at"),after.get("expires_at"));
        assertEquals(initial.get("initial_scope"),after.get("initial_scope"));
        assertEquals("REVOKED",jdbc.queryForObject("SELECT status FROM demo_token",String.class));
    }
    @Test void expiryRemainsHistoricalAndAdditionalFreshIssueDoesNotRequireEnvironmentSlot()throws Exception {
        try(Connection c=source.getConnection()){DemoTokenAdministration.initialize(c,List.of());}
        historical(TOKEN,Instant.parse("2000-01-01T00:00:00Z"));var before=history();var registry=registry(TOKEN);
        assertDoesNotThrow(registry::requireReady);assertNull(registry.resolve(TOKEN));assertEquals(before,history());
        try(Connection c=source.getConnection()){DemoTokenAdministration.issue(c,binding(OTHER,new Actor("fresh-reviewer","LOAN_REVIEWER",Set.of("customer-102"))),Set.of());}
        assertEquals("fresh-reviewer",registry.resolve(OTHER).actorId());assertNull(registry.resolve(TOKEN));
    }
    @Test void changedConfiguredTokenIdentityOrInitialScopeFailsWithoutWrites()throws Exception {
        initialize();var before=history();assertThrows(DemoTokenStore.Unavailable.class,registry(OTHER)::requireReady);
        var store=new JdbcDemoTokenStore(jdbc);
        for(Actor mismatch:List.of(new Actor("wrong","CUSTOMER",ACTOR.customerIds()),new Actor(ACTOR.actorId(),"DEVELOPER",ACTOR.customerIds()),new Actor(ACTOR.actorId(),ACTOR.role(),Set.of()))) {
            assertThrows(DemoTokenStore.Unavailable.class,()->store.lookup(DevActorRegistry.fingerprint(TOKEN),List.of(binding(TOKEN,mismatch))));
            assertEquals(before,history());
        }
    }
    @Test void missingTableAndConnectionFailureAreUnavailableNeverUnknownIdentity()throws Exception {
        initialize();var registry=registry(TOKEN);var before=history();jdbc.execute("ALTER TABLE demo_token RENAME TO hidden_demo_token");
        try{assertThrows(DemoTokenStore.Unavailable.class,()->registry.resolve(TOKEN));}finally{jdbc.execute("ALTER TABLE hidden_demo_token RENAME TO demo_token");}
        assertNotNull(registry.resolve(TOKEN));assertEquals(before,history());
        DataSource broken=new org.springframework.jdbc.datasource.AbstractDataSource(){@Override public Connection getConnection()throws SQLException{throw new SQLException("synthetic failure with private text");}@Override public Connection getConnection(String u,String p)throws SQLException{return getConnection();}};
        var store=new JdbcDemoTokenStore(new JdbcTemplate(broken));var failure=assertThrows(DemoTokenStore.Unavailable.class,()->store.lookup(DevActorRegistry.fingerprint(TOKEN),List.of()));
        assertEquals("Authentication authority is unavailable",failure.getMessage());assertNull(failure.getCause());
    }
    @Test void schemaLocalLedgersDoNotShareIdentityOrScope()throws Exception {
        initialize();String otherSchema="auth_"+UUID.randomUUID().toString().replace("-","");new JdbcTemplate(base()).execute("CREATE SCHEMA "+otherSchema);
        try {
            DataSource separate=source(otherSchema);migrate(separate,otherSchema);
            try(Connection c=separate.getConnection()){DemoTokenAdministration.initialize(c,List.of(binding(TOKEN,new Actor("independent","CUSTOMER",Set.of("customer-102")))));}
            var separateStore=new JdbcDemoTokenStore(new JdbcTemplate(separate));
            assertEquals("independent",separateStore.lookup(DevActorRegistry.fingerprint(TOKEN),List.of()).credential().actor().actorId());assertEquals(ACTOR,registry(TOKEN).resolve(TOKEN));
        } finally {new JdbcTemplate(base()).execute("DROP SCHEMA "+otherSchema+" CASCADE");}
    }
    @Test void ownerDmlCannotChangeIssuanceResurrectOrRemoveHistory()throws Exception {
        initialize();String fingerprint=DevActorRegistry.fingerprint(TOKEN);var before=history();
        for(String sql:List.of("UPDATE demo_token SET issued_at=issued_at-interval '1 second',expires_at=expires_at-interval '1 second',revision=revision+1",
            "UPDATE demo_token SET actor_id='changed',revision=revision+1","UPDATE demo_token SET initial_scope=ARRAY[]::text[],revision=revision+1",
            "UPDATE demo_token SET fingerprint=decode('"+DevActorRegistry.fingerprint(OTHER)+"','hex'),revision=revision+1",
            "DELETE FROM demo_token","TRUNCATE demo_token","UPDATE demo_auth_registry SET registry_id=gen_random_uuid()","DELETE FROM demo_auth_registry","TRUNCATE demo_auth_registry CASCADE")) {
            assertThrows(org.springframework.dao.DataAccessException.class,()->jdbc.execute(sql));assertEquals(before,history());
        }
        try(Connection c=source.getConnection()){DemoTokenAdministration.revokeFingerprint(c,fingerprint);}
        var revoked=history();
        assertThrows(org.springframework.dao.DataAccessException.class,()->jdbc.execute("UPDATE demo_token SET status='ACTIVE',revoked_at=NULL,revision=revision+1"));assertEquals(revoked,history());
        try(Connection c=source.getConnection()){assertThrows(SQLException.class,()->DemoTokenAdministration.issue(c,binding(TOKEN,ACTOR),Set.of()));}
        assertEquals(revoked,history());
    }
    @Test void duplicateInitializersAndIssuersHaveOneWinnerAndNeverUpsert()throws Exception {
        assertEquals(1,race(()->{try(Connection c=source.getConnection()){DemoTokenAdministration.initialize(c,List.of(binding(TOKEN,ACTOR)));}}));
        String initial=jdbc.queryForObject("SELECT to_jsonb(t)::text FROM demo_token t WHERE fingerprint=decode(?, 'hex')",String.class,DevActorRegistry.fingerprint(TOKEN));
        assertEquals(1,race(()->{try(Connection c=source.getConnection()){DemoTokenAdministration.issue(c,binding(OTHER,ACTOR),Set.of());}}));
        assertEquals(2,history().size());
        assertEquals(initial,jdbc.queryForObject("SELECT to_jsonb(t)::text FROM demo_token t WHERE fingerprint=decode(?, 'hex')",String.class,DevActorRegistry.fingerprint(TOKEN)));
    }
    @Test void replacementIsAtomicAndScopeUpdateCannotUndoConcurrentRevocation()throws Exception {
        initialize();var first=registry(TOKEN);
        try(Connection c=source.getConnection()){DemoTokenAdministration.issue(c,binding(OTHER,ACTOR),Set.of(DevActorRegistry.fingerprint(TOKEN)));}
        assertNull(first.resolve(TOKEN));assertNotNull(first.resolve(OTHER));
        var before=history();try(Connection c=source.getConnection()){assertThrows(SQLException.class,()->DemoTokenAdministration.issue(c,binding(THIRD,ACTOR),Set.of("0".repeat(64))));}assertEquals(before,history());
        try(var executor=Executors.newFixedThreadPool(2)) {
            Future<?> revoke=executor.submit(()->{try(Connection c=source.getConnection()){DemoTokenAdministration.revokeActor(c,ACTOR.actorId());}catch(Exception e){throw new RuntimeException(e);}});
            Future<?> scope=executor.submit(()->{try(Connection c=source.getConnection()){DemoTokenAdministration.updateScope(c,ACTOR.actorId(),Set.of("customer-102"));}catch(Exception e){throw new RuntimeException(e);}});
            revoke.get(15,TimeUnit.SECONDS);scope.get(15,TimeUnit.SECONDS);
        }
        assertNull(first.resolve(OTHER));assertEquals(2,jdbc.queryForObject("SELECT count(*) FROM demo_token WHERE status='REVOKED'",Integer.class));
    }
    @Test void actorWideRevocationAndFreshIssueHaveAnObservableSerialOrder()throws Exception {
        initialize();var gate=new CountDownLatch(1);
        try(var executor=Executors.newFixedThreadPool(2)) {
            var revoke=executor.submit(()->{gate.await();try(Connection c=source.getConnection()){return DemoTokenAdministration.revokeActor(c,ACTOR.actorId());}});
            var issue=executor.submit(()->{gate.await();try(Connection c=source.getConnection()){DemoTokenAdministration.issue(c,binding(OTHER,ACTOR),Set.of());}return true;});
            gate.countDown();int revoked=revoke.get(15,TimeUnit.SECONDS);assertTrue(issue.get(15,TimeUnit.SECONDS));
            assertTrue(revoked==1||revoked==2);
            String oldStatus=jdbc.queryForObject("SELECT status FROM demo_token WHERE fingerprint=decode(?, 'hex')",String.class,DevActorRegistry.fingerprint(TOKEN));
            String newStatus=jdbc.queryForObject("SELECT status FROM demo_token WHERE fingerprint=decode(?, 'hex')",String.class,DevActorRegistry.fingerprint(OTHER));
            assertEquals("REVOKED",oldStatus);assertEquals(revoked==1?"ACTIVE":"REVOKED",newStatus);
            assertEquals(revoked==1,registry(TOKEN).resolve(OTHER)!=null);
        }
    }
    @Test void migrationRemovesInheritedRuntimeMutationGrantsAndPublicFunctionAccess()throws Exception {
        JdbcTemplate root=new JdbcTemplate(base());
        assertEquals(0,root.queryForObject("SELECT count(*) FROM pg_roles WHERE rolname='fuse_runtime'",Integer.class),"This privilege gate requires the owned ephemeral cluster's unused standard role name");
        String aclSchema=schema+"_acl";root.execute("CREATE ROLE fuse_runtime NOLOGIN");
        try {
            root.execute("CREATE SCHEMA "+aclSchema);
            root.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA "+aclSchema+" GRANT ALL ON TABLES TO fuse_runtime");
            DataSource separate=source(aclSchema);migrate(separate,aclSchema);
            root.execute("GRANT USAGE ON SCHEMA "+aclSchema+" TO fuse_runtime");
            try(Connection owner=separate.getConnection()){DemoTokenAdministration.initialize(owner,List.of(binding(TOKEN,ACTOR)));}
            try(Connection runtime=separate.getConnection();Statement statement=runtime.createStatement()) {
                statement.execute("SET ROLE fuse_runtime");
                try(ResultSet rows=statement.executeQuery("SELECT count(*) FROM demo_token")){assertTrue(rows.next());assertEquals(1,rows.getInt(1));}
                for(String sql:List.of("INSERT INTO demo_auth_registry SELECT * FROM demo_auth_registry",
                    "INSERT INTO demo_token SELECT * FROM demo_token","UPDATE demo_token SET current_scope=ARRAY[]::text[],revision=revision+1",
                    "DELETE FROM demo_token","TRUNCATE demo_token","UPDATE demo_auth_registry SET format_version=1",
                    "DELETE FROM demo_auth_registry","TRUNCATE demo_auth_registry CASCADE","ALTER TABLE demo_token ADD COLUMN unexpected text"))
                    assertThrows(SQLException.class,()->statement.execute(sql));
                try(ResultSet rows=statement.executeQuery("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='"+aclSchema+"' AND p.proname IN ('protect_demo_token','protect_demo_registry') AND has_function_privilege(current_user,p.oid,'EXECUTE')")) {
                    assertTrue(rows.next());assertEquals(0,rows.getInt(1));
                }
            }
        } finally {
            root.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA "+aclSchema+" REVOKE ALL ON TABLES FROM fuse_runtime");
            root.execute("DROP SCHEMA IF EXISTS "+aclSchema+" CASCADE");root.execute("DROP ROLE fuse_runtime");
        }
    }
    @FunctionalInterface private interface Attempt {void run()throws Exception;}
    private int race(Attempt attempt)throws Exception {
        var gate=new CountDownLatch(1);int succeeded=0;
        try(var executor=Executors.newFixedThreadPool(2)) {
            List<Future<Boolean>> attempts=new ArrayList<>();for(int i=0;i<2;i++)attempts.add(executor.submit(()->{gate.await();try{attempt.run();return true;}catch(SQLException expectedConflict){return false;}}));
            gate.countDown();for(var future:attempts)if(future.get(15,TimeUnit.SECONDS))succeeded++;
        }
        return succeeded;
    }
}
