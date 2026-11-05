package com.finsec.fuse.migration;

import com.finsec.fuse.reimplementation.cli.MigrationArguments;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.migration.MigrationCommandRunner.*;

/** Synthetic SPI tests only: exact public SQL resource reads, never execute SQL or open JDBC/native FDs. */
final class DatabaseMigratorTest {
    private static String[] args(String schema){return new String[]{"fresh-init","--schema",schema,"--credential-input-fd","7","--expect-empty"};}
    private static ConnectionBinding binding(long oid){return new ConnectionBinding("synthetic-database","synthetic_schema",oid,
            "synthetic-owner","synthetic-owner","synthetic-session",9,List.of("synthetic_schema"));}
    private static Bundle bundle() throws Exception {
        var bytes=new LinkedHashMap<String,byte[]>();
        for(var migration:migrations()){
            try(var in=DatabaseMigratorTest.class.getResourceAsStream("/"+migration.resource())){
                assertNotNull(in);var raw=in.readNBytes(migration.bytes()+1);assertEquals(migration.bytes(),raw.length);assertEquals(-1,in.read());
                bytes.put(migration.resource(),raw);
            }
        }
        return new Bundle(bytes);
    }
    private static final class FakeSession extends Session {
        int applies,observations,cleanups,leaseChecks;int failAt,unknownAt;boolean cleanupUnknown,throwApply,throwCleanup;
        boolean drift,nonempty,historyInitially,inventoryUnknown,wrongOwner,wrongPath;
        final List<Integer> versions=new ArrayList<>();
        final NamespaceLease lease=new NamespaceLease(){public void requireCurrent(ConnectionBinding connection){leaseChecks++;assertEquals(binding(17),connection);}};
        public NamespaceLease exclusiveNamespace(){return lease;}
        public Observation observe(){
            observations++;
            var b=binding(drift&&applies>0?18:17);
            if(wrongOwner)b=new ConnectionBinding(b.databaseIdentity(),b.schema(),b.namespaceOid(),b.currentRole(),"another-owner",b.sessionRole(),b.backendPid(),b.searchPath());
            if(wrongPath)b=new ConnectionBinding(b.databaseIdentity(),b.schema(),b.namespaceOid(),b.currentRole(),b.ownerRole(),b.sessionRole(),b.backendPid(),List.of("public"));
            return new Observation(b,inventoryUnknown?Inventory.UNKNOWN:Inventory.COMPLETE_ALL_OBJECT_KINDS,
                    applies==0?(nonempty?1:0):applies,historyInitially||!versions.isEmpty());
        }
        public Step apply(Migration migration,Bundle loaded,ConnectionBinding expected,NamespaceLease supplied){
            assertSame(lease,supplied);assertEquals(binding(17),expected);assertTrue(leaseChecks>=applies+2);
            assertEquals(migration.bytes(),loaded.bytes(migration).length);applies++;
            if(throwApply)throw new IllegalStateException("synthetic-driver-secret-canary");
            if(migration.version()==unknownAt)return new Step(migration.version(),StepStatus.UNKNOWN,expected);
            if(migration.version()==failAt)return new Step(migration.version(),StepStatus.KNOWN_NOT_APPLIED,expected);
            versions.add(migration.version());return new Step(migration.version(),StepStatus.COMMITTED,expected);
        }
        public Cleanup cleanup(){cleanups++;if(throwCleanup)throw new IllegalStateException("synthetic-cleanup-secret-canary");return cleanupUnknown?Cleanup.UNKNOWN:Cleanup.CONFIRMED;}
    }
    private static final class Backend extends PreparedBackend {
        final Bundle loaded;final FakeSession session=new FakeSession();int opens;boolean missingEngine;String database="synthetic-database";
        Backend() throws Exception {loaded=DatabaseMigratorTest.bundle();}
        public Engine engine(){return missingEngine?null:new Engine("synthetic-engine-artifact","synthetic-version","a".repeat(64),History.MANAGED_PER_MIGRATION);}
        public String expectedDatabaseIdentity(){return database;}
        public Bundle bundle(){return loaded;}
        public Session open(MigrationArguments input){opens++;assertEquals(7,input.credentialInputFd());return session;}
    }
    @Test void absentAdapterAndMalformedArgumentsHaveNoResourceEffects(){
        assertEquals(3,DatabaseMigrator.execute(args("synthetic_schema"),null).exitCode());
        assertEquals(Status.UNCONFIGURED,DatabaseMigrator.execute(args("synthetic_schema"),null).status());
        assertEquals(2,DatabaseMigrator.execute(new String[]{"migrate"},null).exitCode());
        assertEquals(Cleanup.NOT_OPENED,DatabaseMigrator.execute(args("synthetic_schema"),null).cleanup());
    }
    @Test void reservedNamespaceAndMissingEngineNeverOpenSession() throws Exception {
        var backend=new Backend();assertEquals(2,DatabaseMigrator.execute(args("public"),backend).exitCode());
        backend.missingEngine=true;assertEquals(3,DatabaseMigrator.execute(args("synthetic_schema"),backend).exitCode());assertEquals(0,backend.opens);
    }
    @Test void exactNinePinnedResourcesUseLeaseAndConnectionBeforeEachVersion() throws Exception {
        var backend=new Backend();var out=DatabaseMigrator.execute(args("synthetic_schema"),backend);
        assertEquals(Status.FRESH_INIT_CONFIRMED,out.status());assertEquals(0,out.exitCode());
        assertEquals(List.of(1,2,3,4,5,6,7,8,9),out.confirmedVersions());assertEquals(out.confirmedVersions(),backend.session.versions);
        assertEquals(9,backend.session.applies);assertEquals(1,backend.opens);assertEquals(1,backend.session.cleanups);
        assertTrue(backend.session.leaseChecks>=11);assertFalse(out.executionAuthorityGranted());
    }
    @Test void allObjectInventoryHistoryOwnerAndSearchPathRefuseBeforeMigration() throws Exception {
        for(int arm=0;arm<5;arm++){
            var b=new Backend();b.session.nonempty=arm==0;b.session.historyInitially=arm==1;b.session.inventoryUnknown=arm==2;
            b.session.wrongOwner=arm==3;b.session.wrongPath=arm==4;
            var out=DatabaseMigrator.execute(args("synthetic_schema"),b);
            assertEquals(Status.TARGET_REFUSED,out.status());assertEquals(2,out.exitCode());assertEquals(0,b.session.applies);assertEquals(1,b.session.cleanups);
        }
    }
    @Test void wrongPreparedDatabaseIdentityRefusesWithoutMigration() throws Exception {
        var b=new Backend();b.database="another-database";var out=DatabaseMigrator.execute(args("synthetic_schema"),b);
        assertEquals(Status.TARGET_REFUSED,out.status());assertEquals(0,b.session.applies);assertEquals(2,out.exitCode());
    }
    @Test void laterKnownFailurePreservesCommittedPrefixWithoutRetry() throws Exception {
        var b=new Backend();b.session.failAt=4;var out=DatabaseMigrator.execute(args("synthetic_schema"),b);
        assertEquals(Status.PARTIALLY_APPLIED,out.status());assertEquals(List.of(1,2,3),out.confirmedVersions());assertEquals(5,out.exitCode());
        assertEquals(4,b.session.applies);assertEquals(1,b.session.cleanups);assertFalse(out.effectUnknown());
    }
    @Test void uncertainCommitRetainsPrefixAndHasPriorityOverPartial() throws Exception {
        var b=new Backend();b.session.unknownAt=3;var out=DatabaseMigrator.execute(args("synthetic_schema"),b);
        assertEquals(Status.MIGRATION_RESULT_UNKNOWN,out.status());assertEquals(List.of(1,2),out.confirmedVersions());assertEquals(4,out.exitCode());assertTrue(out.effectUnknown());assertEquals(3,b.session.applies);
    }
    @Test void driftStopsBeforeNextVersionAndNeverReopens() throws Exception {
        var b=new Backend();b.session.drift=true;var out=DatabaseMigrator.execute(args("synthetic_schema"),b);
        assertEquals(4,out.exitCode());assertEquals(List.of(1),out.confirmedVersions());assertEquals(1,b.session.applies);assertEquals(1,b.opens);assertEquals(1,b.session.cleanups);
    }
    @Test void cleanupUncertaintyRetainsAllConfirmedVersionsAndOverridesSuccessOrPartial() throws Exception {
        for(boolean partial:new boolean[]{false,true}){
            var b=new Backend();b.session.cleanupUnknown=true;if(partial)b.session.failAt=3;
            var out=DatabaseMigrator.execute(args("synthetic_schema"),b);
            assertEquals(4,out.exitCode());assertEquals(Cleanup.UNKNOWN,out.cleanup());assertEquals(partial?List.of(1,2):List.of(1,2,3,4,5,6,7,8,9),out.confirmedVersions());
        }
    }
    @Test void ordinaryDriverAndCleanupErrorsAreFixedRedactedUnknown() throws Exception {
        var b=new Backend();b.session.throwApply=true;b.session.throwCleanup=true;
        var out=DatabaseMigrator.execute(args("synthetic_schema"),b);
        assertEquals(4,out.exitCode());assertTrue(out.effectUnknown());assertEquals(Cleanup.UNKNOWN,out.cleanup());assertEquals(1,b.session.applies);assertEquals(1,b.session.cleanups);
        assertFalse(out.toString().contains("secret-canary"));assertEquals("MigrationOutcome[REDACTED]",out.toString());assertTrue(out.confirmedVersions().isEmpty());
    }
}
