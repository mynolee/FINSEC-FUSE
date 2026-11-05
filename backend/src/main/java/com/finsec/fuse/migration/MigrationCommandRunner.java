package com.finsec.fuse.migration;

import com.finsec.fuse.reimplementation.cli.MigrationArguments;
import java.security.MessageDigest;
import java.util.*;

/** Fresh-only orchestration. No operational backend is supplied by this module. */
public final class MigrationCommandRunner {
    private MigrationCommandRunner() {}
    public enum Status { FRESH_INIT_CONFIRMED, INPUT_REJECTED, UNCONFIGURED, TARGET_REFUSED,
        PARTIALLY_APPLIED, MIGRATION_RESULT_UNKNOWN }
    public enum Cleanup { NOT_OPENED, CONFIRMED, UNKNOWN }
    public enum Inventory { COMPLETE_ALL_OBJECT_KINDS, UNKNOWN }
    public enum History { MANAGED_PER_MIGRATION }
    public enum StepStatus { COMMITTED, KNOWN_NOT_APPLIED, UNKNOWN }
    public record Migration(int version,String resource,int bytes,String sha256) {
        public Migration { if(version<1||resource==null||bytes<1||sha256==null)throw invalid(); }
        @Override public String toString(){return "PinnedMigration[REDACTED]";}
    }
    private static final List<Migration> MIGRATIONS=List.of(
        new Migration(1,"db/migration/V1__fuse_core.sql",17300,"5c1b8ef166c283c1e0fd83aaf3a68756403080e88900312f6bc9a836efd6174c"),
        new Migration(2,"db/migration/V2__experiments.sql",1196,"eeee1b0775341995f55ae28a9286870f61d0b3868af958063fd5f06456941263"),
        new Migration(3,"db/migration/V3__immutable_agent_results.sql",1682,"d3361dba7952de3641d4adb866a13060e35dadfe024763599ed19c0948c6e1bd"),
        new Migration(4,"db/migration/V4__pre_execution_quarantine_holds.sql",742,"b0433f1ee243026e2aa8e6fa5cb67daaf7d4100aa7588d847b9bfb8d73ff6b6b"),
        new Migration(5,"db/migration/V5__experiment_arm_bindings.sql",739,"b33571bbfe9dacd831bfdb54f047221afe097ad98eb441559873d0461f527f42"),
        new Migration(6,"db/migration/V6__durable_demo_tokens.sql",4348,"ef5e08f186165aac50a8587cd07111fdd0c5570e8b552d03860d88cdc9cb9423"),
        new Migration(7,"db/migration/V7__protect_flyway_history.sql",877,"ffd4789c8767534ea28269b3132d56ad558625f61918f5692129316839c3d4b7"),
        new Migration(8,"db/migration/V8__protect_audit_and_token_boundaries.sql",2273,"41c9a12a4c25cbaa83ee93afc95f7b9160a839f7501ade9b40f21a6402c42c1d"),
        new Migration(9,"db/migration/V9__immutable_token_selection_ids.sql",2273,"173397633339a0d7b0ad7baacc7825eee68a2a93c002a0ab6bf984942d681a1f"));
    public static List<Migration> migrations(){return MIGRATIONS;}
    public record Engine(String artifact,String version,String artifactSha256,History history) {
        public Engine {text(artifact);text(version);hash(artifactSha256);Objects.requireNonNull(history);}
        @Override public String toString(){return "PreparedMigrationEngine[REDACTED]";}
    }
    /** Loaded exact resources only. No discovery, SQL splitting or source-SHA/history-checksum equivalence. */
    public static final class Bundle {
        private final Map<String,byte[]> resources;
        public Bundle(Map<String,byte[]> supplied){
            if(supplied==null||supplied.size()!=MIGRATIONS.size())throw invalid();
            var copy=new LinkedHashMap<String,byte[]>();
            for(var m:MIGRATIONS){
                byte[] raw=supplied.get(m.resource());if(raw==null)throw invalid();raw=raw.clone();
                if(raw.length!=m.bytes()||!digest(raw).equals(m.sha256()))throw invalid();copy.put(m.resource(),raw);
            }
            if(!supplied.keySet().equals(copy.keySet()))throw invalid();resources=Collections.unmodifiableMap(copy);
        }
        public byte[] bytes(Migration m){
            if(!MIGRATIONS.contains(m))throw invalid();return resources.get(m.resource()).clone();
        }
        @Override public String toString(){return "PinnedMigrationBundle[REDACTED]";}
    }
    /** Data identity is not a database authentication/ownership witness. */
    public record ConnectionBinding(String databaseIdentity,String schema,long namespaceOid,String currentRole,
            String ownerRole,String sessionRole,long backendPid,List<String> searchPath) {
        public ConnectionBinding {text(databaseIdentity);text(schema);text(currentRole);text(ownerRole);text(sessionRole);
            if(namespaceOid<1||backendPid<1)throw invalid();searchPath=List.copyOf(searchPath);}
        @Override public String toString(){return "MigrationConnectionBinding[REDACTED]";}
    }
    public record Observation(ConnectionBinding binding,Inventory inventory,long objectCount,boolean historyPresent) {
        public Observation {Objects.requireNonNull(binding);Objects.requireNonNull(inventory);if(objectCount<0)throw invalid();}
        @Override public String toString(){return "MigrationObservation[REDACTED]";}
    }
    public record Step(int version,StepStatus status,ConnectionBinding connection) {
        public Step {if(version<1)throw invalid();Objects.requireNonNull(status);Objects.requireNonNull(connection);}
        @Override public String toString(){return "MigrationStep[REDACTED]";}
    }
    /** Only trusted in-package native adapters may construct these SPI implementations.
     * No implementation exists here. A client-supplied record/boolean cannot mint this lease. */
    public abstract static class NamespaceLease {
        NamespaceLease() {}
        public abstract void requireCurrent(ConnectionBinding connection);
    }
    public abstract static class PreparedBackend {
        PreparedBackend() {}
        /** Must be an already admitted native/admin/backend with an exact loaded bundle and engine.
         * This method must not connect/read descriptors/acquire entropy or perform effects. */
        public abstract Engine engine();
        public abstract String expectedDatabaseIdentity();
        public abstract Bundle bundle();
        public abstract Session open(MigrationArguments arguments);
    }
    public abstract static class Session {
        Session() {}
        public abstract NamespaceLease exclusiveNamespace();
        /** Actual backend connection metadata, never a cached request assertion. */
        public abstract Observation observe();
        /** Adapter must use exactly this resource with pinned engine/history lifecycle; no alternate
         * connection is usable without the same current metadata/lease checks before its writes. */
        public abstract Step apply(Migration migration,Bundle bundle,ConnectionBinding expected,NamespaceLease lease);
        /** Close only owned resources/own active unconfirmed transaction; never erase prior commits. */
        public abstract Cleanup cleanup();
    }
    public record Outcome(Status status,List<Integer> confirmedVersions,Cleanup cleanup,boolean effectUnknown) {
        public Outcome {Objects.requireNonNull(status);Objects.requireNonNull(cleanup);confirmedVersions=List.copyOf(confirmedVersions);
            for(int i=0;i<confirmedVersions.size();i++)if(confirmedVersions.get(i)==null||confirmedVersions.get(i)!=i+1)throw invalid();
            if(confirmedVersions.size()>9)throw invalid();
            if(status==Status.FRESH_INIT_CONFIRMED&&(confirmedVersions.size()!=9||cleanup!=Cleanup.CONFIRMED||effectUnknown))throw invalid();
            if(status==Status.PARTIALLY_APPLIED&&(confirmedVersions.isEmpty()||confirmedVersions.size()==9||cleanup!=Cleanup.CONFIRMED||effectUnknown))throw invalid();
            if((status==Status.UNCONFIGURED||status==Status.INPUT_REJECTED)&&(cleanup!=Cleanup.NOT_OPENED||!confirmedVersions.isEmpty()||effectUnknown))throw invalid();
            if(status==Status.TARGET_REFUSED&&(!confirmedVersions.isEmpty()||effectUnknown))throw invalid();}
        public int exitCode(){
            if(effectUnknown||cleanup==Cleanup.UNKNOWN||status==Status.MIGRATION_RESULT_UNKNOWN)return 4;
            return switch(status){case FRESH_INIT_CONFIRMED->0;case INPUT_REJECTED,TARGET_REFUSED->2;
                case UNCONFIGURED->3;case PARTIALLY_APPLIED->5;case MIGRATION_RESULT_UNKNOWN->4;};
        }
        public boolean executionAuthorityGranted(){return false;}
        @Override public String toString(){return "MigrationOutcome[REDACTED]";}
    }
    public static Outcome run(MigrationArguments args,PreparedBackend backend){
        if(args==null)return outcome(Status.INPUT_REJECTED,List.of(),Cleanup.NOT_OPENED,false);
        if(reserved(args.schema()))return outcome(Status.TARGET_REFUSED,List.of(),Cleanup.NOT_OPENED,false);
        if(backend==null)return outcome(Status.UNCONFIGURED,List.of(),Cleanup.NOT_OPENED,false);
        Engine engine;Bundle bundle;String database;
        try{engine=backend.engine();bundle=backend.bundle();database=backend.expectedDatabaseIdentity();text(database);}
        catch(RuntimeException unavailable){return outcome(Status.UNCONFIGURED,List.of(),Cleanup.NOT_OPENED,false);}
        if(engine==null||bundle==null)return outcome(Status.UNCONFIGURED,List.of(),Cleanup.NOT_OPENED,false);
        var confirmed=new ArrayList<Integer>();Session session=null;Cleanup cleanup=Cleanup.UNKNOWN;
        Status status=Status.MIGRATION_RESULT_UNKNOWN;boolean unknown=true;
        try{
            session=backend.open(args);if(session==null)throw invalid();
            var lease=Objects.requireNonNull(session.exclusiveNamespace());var initial=Objects.requireNonNull(session.observe());
            if(!admitted(args,initial)||!initial.binding().databaseIdentity().equals(database)){status=Status.TARGET_REFUSED;unknown=false;}
            else {
                var fixed=initial.binding();lease.requireCurrent(fixed);status=Status.FRESH_INIT_CONFIRMED;unknown=false;
                for(var migration:MIGRATIONS){
                    var current=Objects.requireNonNull(session.observe());
                    if(!current.binding().equals(fixed)||current.inventory()!=Inventory.COMPLETE_ALL_OBJECT_KINDS)throw invalid();
                    if(confirmed.isEmpty()&&(current.objectCount()!=0||current.historyPresent()))throw invalid();
                    if(!confirmed.isEmpty()&&!current.historyPresent())throw invalid();
                    lease.requireCurrent(current.binding());unknown=true;
                    var step=Objects.requireNonNull(session.apply(migration,bundle,fixed,lease));
                    if(step.version()!=migration.version()||!step.connection().equals(fixed))throw invalid();
                    if(step.status()==StepStatus.UNKNOWN)break;
                    unknown=false;
                    if(step.status()==StepStatus.KNOWN_NOT_APPLIED){status=confirmed.isEmpty()?Status.TARGET_REFUSED:Status.PARTIALLY_APPLIED;break;}
                    confirmed.add(migration.version());
                }
                if(!unknown&&confirmed.size()==9){
                    var after=Objects.requireNonNull(session.observe());
                    if(!after.binding().equals(fixed)||after.inventory()!=Inventory.COMPLETE_ALL_OBJECT_KINDS||!after.historyPresent())throw invalid();
                    lease.requireCurrent(after.binding());
                }
                if(unknown)status=Status.MIGRATION_RESULT_UNKNOWN;
                else if(status==Status.FRESH_INIT_CONFIRMED&&confirmed.size()!=9)status=Status.MIGRATION_RESULT_UNKNOWN;
            }
        }catch(RuntimeException unavailable){status=Status.MIGRATION_RESULT_UNKNOWN;unknown=true;}
        finally{
            if(session!=null){try{cleanup=session.cleanup();if(cleanup!=Cleanup.CONFIRMED)cleanup=Cleanup.UNKNOWN;}
                catch(RuntimeException unavailable){cleanup=Cleanup.UNKNOWN;}}
        }
        if(cleanup==Cleanup.UNKNOWN)status=Status.MIGRATION_RESULT_UNKNOWN;
        return outcome(status,confirmed,cleanup,unknown);
    }
    private static boolean admitted(MigrationArguments args,Observation o){
        var b=o.binding();return args.expectEmpty()&&b.schema().equals(args.schema())&&!reserved(b.schema())
            &&b.currentRole().equals(b.ownerRole())&&b.searchPath().equals(List.of(args.schema()))
            &&o.inventory()==Inventory.COMPLETE_ALL_OBJECT_KINDS&&o.objectCount()==0&&!o.historyPresent();
    }
    private static boolean reserved(String schema){String s=schema.toLowerCase(Locale.ROOT);return s.equals("public")||s.equals("information_schema")||s.startsWith("pg_");}
    private static Outcome outcome(Status s,List<Integer> versions,Cleanup c,boolean unknown){return new Outcome(s,versions,c,unknown);}
    private static String digest(byte[] bytes){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
        catch(java.security.NoSuchAlgorithmException unavailable){throw invalid();}}
    private static void text(String s){if(s==null||s.isBlank()||s.length()>256)throw invalid();}
    private static void hash(String s){if(s==null||!s.matches("[0-9a-f]{64}"))throw invalid();}
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("MIGRATION_UNCONFIRMED");}
}
