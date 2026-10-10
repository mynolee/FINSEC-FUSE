package com.finsec.fuse.testing;

import com.finsec.fuse.auth.DevActorRegistry;
import com.finsec.fuse.workflow.KycContract;
import com.sun.net.httpserver.HttpServer;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.sql.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import tools.jackson.databind.json.JsonMapper;

/** Real process-start acceptance: production Spring beans and scheduler, owned PostgreSQL only. */
public final class StartupAdmissionHarness {
    private static final JsonMapper JSON=JsonMapper.builder().build();
    private static final List<String> CASES=List.of("MISSING_KEY","MISSING_SERVICE_TOKEN","INVALID_POLICY",
        "MISSING_POLICY","DB_UNAVAILABLE","ORDINARY_DEVELOPER_TOKEN","MISSING_FUSE","MISSING_KYC",
        "MISSING_LOAN","MISSING_PAYMENT","VALID_REPLAY_NO_MODEL_KEY");
    private static final HttpClient HTTP=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).build();
    private final Path root,report;
    private final List<Map<String,Object>> results=new ArrayList<>();
    private final List<Process> children=new CopyOnWriteArrayList<>(),databases=new CopyOnWriteArrayList<>();
    private final Set<Integer> ports=new HashSet<>();
    private final Map<Process,Path> startupMarkers=new HashMap<>();
    private enum Stage { DATABASE_START, FIXTURE_SETUP, PREPARE_START, PREPARE_ADMISSION, BASELINE,
        SUBJECT_START, READINESS_REFUSAL, REFUSAL_INVARIANTS, REPAIR, RECOVERY_READINESS,
        RECOVERY_CLAIM, VALID_CONTROL, INVALID_EXIT, EXPECTED_FAILURE_CAUSE, INVALID_INVARIANTS, FINAL_INVARIANTS }
    private enum FailureCategory { NONE, ASSERTION_FAILED, EXECUTION_FAILED }
    private String currentScenario="NONE";
    private Stage currentStage=Stage.DATABASE_START;
    private void checkpoint(Stage stage)throws Exception {
        currentStage=stage;writeDiagnostic(FailureCategory.NONE);
    }
    private void writeDiagnostic(FailureCategory category)throws Exception {
        Files.writeString(report.resolveSibling("startup-admission-diagnostic.json"),JSON.writeValueAsString(Map.of(
            "schemaVersion","FUSE-STARTUP-DIAGNOSTIC-1","status",category==FailureCategory.NONE?"RUNNING":"FAIL",
            "scenario",currentScenario,"stage",currentStage.name(),"failureCategory",category.name()))+"\n");
    }
    private EmbeddedPostgres pg;
    private HttpServer agent;
    private ExecutorService agentExecutor;
    private StartupAdmissionHarness(Path root,Path report){this.root=root;this.report=report;}

    public static void main(String[] args)throws Exception {
        if(args.length!=2)throw new IllegalArgumentException("Expected empty temporary work directory and report");
        Path root=Path.of(args[0]).toRealPath();
        try(var entries=Files.list(root)){check(entries.findAny().isEmpty(),"Work directory must be empty");}
        var harness=new StartupAdmissionHarness(root,Path.of(args[1]).toAbsolutePath());
        Thread hook=new Thread(harness::cleanup,"startup-admission-cleanup");
        Runtime.getRuntime().addShutdownHook(hook);
        boolean passed=false;
        try {for(String name:CASES)harness.scenario(name);passed=true;}
        finally {harness.cleanup();harness.writeReport(passed);Runtime.getRuntime().removeShutdownHook(hook);}
        System.out.println("STARTUP_ADMISSION_PASS scenarios="+CASES.size()+" syntheticReplay=true");
    }

    private void scenario(String name)throws Exception {
        Path work=Files.createDirectory(root.resolve(name.toLowerCase(Locale.ROOT)));
        var result=new LinkedHashMap<String,Object>();results.add(result);
        result.put("scenario",name);result.put("verdict","FAIL");result.put("startedAt",Instant.now().toString());
        result.put("worker", "Actual @Scheduled JobWorker configured enabled in subject process; never manually invoked");
        result.put("implementedTestFile", "backend/src/test/java/com/finsec/fuse/testing/StartupAdmissionHarness.java");
        var calls=new AtomicInteger();
        currentScenario=name;
        try {
            checkpoint(Stage.DATABASE_START);
            pg=database(work.resolve("database"),0);String url=pg.getJdbcUrl("postgres","postgres");
            check("16.15".equals(scalar(url,"show server_version")),"PostgreSQL 16.15 required");
            result.put("postgresVersion","16.15");
            checkpoint(Stage.FIXTURE_SETUP);
            byte[] key=new byte[32];new SecureRandom().nextBytes(key);
            Path keyFile=work.resolve("ephemeral-signing-key");Files.write(keyFile,key);privateFile(keyFile);Arrays.fill(key,(byte)0);
            String service=DevActorRegistry.generateToken(),reviewer=DevActorRegistry.generateToken(),developer=DevActorRegistry.generateToken();
            // Fresh scenario setup only; prepare, subject and recovery reuse the unchanged ledger.
            // Keep the connection URL identical to the owned URL checked by the fixture.
            var owner=new org.springframework.jdbc.datasource.DriverManagerDataSource(url,"postgres","");
            org.flywaydb.core.Flyway.configure().dataSource(owner)
                .locations("classpath:db/migration").load().migrate();
            DemoTokenTestFixture.initializeOwned(owner,url,
                Map.of("kyc-service",service,"reviewer",reviewer));
            var originalAuth=snapshot(url);
            agent=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
            agentExecutor=Executors.newVirtualThreadPerTaskExecutor();agent.setExecutor(agentExecutor);
            agent.createContext("/internal/v1/kyc/evaluations",exchange->{
                try(exchange) {
                    calls.incrementAndGet();
                    if(!service.equals(exchange.getRequestHeaders().getFirst("X-Fuse-Service-Token"))){exchange.sendResponseHeaders(403,-1);return;}
                    var input=JSON.readValue(exchange.getRequestBody().readNBytes(65537),KycContract.Input.class);
                    var response=new KycContract.Response(input.requestId(),input.workflowId(),input.generation(),input.runId(),input.inputSnapshotHash(),
                        new KycContract.Proposal(KycContract.ProposalStatus.VERIFIED,input.evidenceFacts().stream().map(KycContract.EvidenceFact::evidenceId).toList(),"Synthetic startup acceptance replay"),
                        new KycContract.ModelMetadata("replay","KYC-PROMPT-1"));
                    byte[] bytes=JSON.writeValueAsBytes(response);exchange.getResponseHeaders().add("Content-Type","application/json");
                    exchange.sendResponseHeaders(200,bytes.length);exchange.getResponseBody().write(bytes);
                }catch(Exception failure){throw new IllegalStateException("Local replay failed",failure);}
            });agent.start();ports.add(agent.getAddress().getPort());
            var base=new ArrayList<String>(List.of("--spring.profiles.active=demo","--server.address=127.0.0.1",
                "--spring.datasource.url="+url,"--spring.datasource.username=postgres","--spring.datasource.password=",
                "--spring.flyway.user=postgres","--spring.flyway.password=","--spring.flyway.enabled=true",
                "--fuse.demo-seed=false","--fuse.worker-enabled=true","--fuse.kyc-mode=replay",
                "--fuse.kyc-base-url=http://127.0.0.1:"+agent.getAddress().getPort(),"--fuse.service-token="+service,
                "--FUSE_SIGNING_KEY_PATH="+keyFile,"--fuse.auth.reviewer-token="+reviewer));
            int preparePort=freePort();var prepareOptions=new ArrayList<>(base);
            replace(prepareOptions,"fuse.demo-seed","true");replace(prepareOptions,"fuse.worker-enabled","false");
            checkpoint(Stage.PREPARE_START);
            Process prepare=launch(work,"prepare","NONE",prepareOptions,preparePort);
            awaitHealth(prepare,preparePort,true);
            checkpoint(Stage.PREPARE_ADMISSION);
            HttpResult queued=post(preparePort,reviewer,UUID.randomUUID(),"102");
            check(queued.status==202 && "ALLOW".equals(queued.body.get("decision")),"Preparation did not create a queued workflow");
            UUID preparedWorkflowId=preparedWorkflowId(queued.body);
            stop(prepare);check(!prepare.isAlive(),"Preparation process did not stop");check(calls.get()==0,"Preparation ran a worker");
            check("1".equals(scalar(url,"SELECT count(*) FROM workflow_job WHERE state='PENDING' AND lease_token IS NULL")),"No unclaimed pending job to challenge scheduler");
            boolean missingAgent=name.startsWith("MISSING_") && Set.of("FUSE","KYC","LOAN","PAYMENT").contains(name.substring(8));
            String absent=missingAgent?name.substring(8):"";
            if(missingAgent)sql(url,"DELETE FROM agent_registry WHERE agent_id='"+absent+"'");
            checkpoint(Stage.BASELINE);
            var before=snapshot(url);result.put("baselineFingerprint",fingerprint(before));
            int databasePort=pg.getPort();
            if(name.equals("DB_UNAVAILABLE")){pg.close();pg=null;check(!portOpen(databasePort),"Database did not stop");}
            var subjectOptions=new ArrayList<>(base);
            switch(name) {
                case "MISSING_KEY" -> replace(subjectOptions,"FUSE_SIGNING_KEY_PATH","");
                case "MISSING_SERVICE_TOKEN" -> replace(subjectOptions,"fuse.service-token","");
                case "ORDINARY_DEVELOPER_TOKEN" -> {
                    replace(subjectOptions,"spring.profiles.active","ordinary");replace(subjectOptions,"fuse.kyc-mode","live");
                    subjectOptions.removeIf(option->option.startsWith("--fuse.auth."));
                    subjectOptions.add("--fuse.auth.developer-token="+developer);
                    // Required normal-profile setting only. Startup must fail before any KYC request.
                }
                default -> { }
            }
            checkpoint(Stage.SUBJECT_START);
            int port=freePort();Process subject=launch(work,"subject",name,subjectOptions,port);
            result.put("subjectPid",subject.pid());
            UUID deniedAction=UUID.randomUUID();
            if(missingAgent) {
                checkpoint(Stage.READINESS_REFUSAL);
                awaitHealth(subject,port,false);
                check(get(port,"/actuator/health/liveness").status==200,"Unready process is not live");
                var denied=post(port,reviewer,deniedAction,"103");
                check(denied.status==503 && "ERROR".equals(denied.body.get("decision")) &&
                    List.of("DEPENDENCY_UNAVAILABLE").equals(denied.body.get("reasonCodes")),"Fresh admission did not return safe infrastructure refusal");
                result.put("livenessStatus",200);result.put("readinessStatus",503);result.put("admissionStatus",denied.status);
                // More than six actual configured 500ms worker periods; compare full durable rows throughout.
                checkpoint(Stage.REFUSAL_INVARIANTS);
                long until=System.nanoTime()+Duration.ofMillis(3500).toNanos();int observations=0;
                do {check(subject.isAlive(),"Unready child exited");check(before.equals(snapshot(url)),"Unready scheduled worker or refused request mutated durable rows");
                    check(calls.get()==0,"Unready scheduler called the KYC endpoint");observations++;Thread.sleep(100);
                }while(System.nanoTime()<until);
                result.put("unchangedDatabaseObservations",observations);result.put("noScheduledClaim",true);
                result.put("refusalFingerprint",fingerprint(snapshot(url)));
                checkpoint(Stage.REPAIR);
                String role=switch(absent){case "FUSE"->"FUSE_WORKER";default->absent;};
                String auth=switch(absent){case "FUSE"->"fuse-worker";case "KYC"->"kyc-service";case "LOAN"->"loan-agent";default->"payment-agent";};
                sql(url,"INSERT INTO agent_registry(agent_id,version,role,auth_subject,status) VALUES('"+absent+"',1,'"+role+"','"+auth+"','ACTIVE')");
                result.put("repair","Explicitly restore only the removed registry entry; same process and unchanged config");
                checkpoint(Stage.RECOVERY_READINESS);
                awaitHealth(subject,port,true);checkpoint(Stage.RECOVERY_CLAIM);awaitClaim(url,preparedWorkflowId,calls,subject);
                check(post(port,reviewer,deniedAction,"103").status==202,"Same previously refused action did not recover");
                result.put("recovery", "Same-process readiness UP, scheduled KYC claim and previously refused action accepted");
            }else if(name.equals("VALID_REPLAY_NO_MODEL_KEY")) {
                checkpoint(Stage.VALID_CONTROL);
                awaitHealth(subject,port,true);check(get(port,"/actuator/health/liveness").status==200,"Valid process not live");
                awaitClaim(url,preparedWorkflowId,calls,subject);result.put("livenessStatus",200);result.put("readinessStatus",200);
                result.put("control","Queued job consumed by actual scheduler with local synthetic REPLAY and no external model key");
            }else {
                checkpoint(Stage.INVALID_EXIT);
                long until=System.nanoTime()+Duration.ofSeconds(65).toNanos();int probes=0;
                while(subject.isAlive() && System.nanoTime()<until) {
                    check(get(port,"/actuator/health/readiness").status!=200,"Invalid startup became ready");
                    int status=post(port,reviewer,deniedAction,"103").status;
                    check(status<200 || status>=300,"Invalid startup admitted business");probes++;Thread.sleep(100);
                }
                check(!subject.isAlive() && subject.exitValue()!=0,"Invalid startup did not exit with failure within bound");
                checkpoint(Stage.EXPECTED_FAILURE_CAUSE);
                String log=Files.readString(work.resolve("subject.log"));
                boolean expectedCause=switch(name){
                    case "MISSING_KEY" -> log.contains("Signing key configuration is required");
                    case "MISSING_SERVICE_TOKEN" -> log.contains("A separate strong internal service token is required");
                    case "MISSING_POLICY" -> log.contains("FileNotFoundException") && log.contains("config/demo_policy.json");
                    case "INVALID_POLICY" -> log.contains("Invalid FUSE policy configuration");
                    case "ORDINARY_DEVELOPER_TOKEN" -> log.contains("Development token registry is forbidden in normal runtime") ||
                        log.contains("Development authentication requires an exclusively demo/test profile");
                    case "DB_UNAVAILABLE" -> log.contains("org.postgresql.util.PSQLException") && log.contains("refused") && log.contains(":"+databasePort);
                    default -> false;
                };
                check(expectedCause,"Child failed for an unexpected reason; inspect private local log");
                check(!Files.exists(startupMarkers.get(subject)),"Invalid configuration completed startup");
                result.put("expectedFailureCauseVerified",true);
                checkpoint(Stage.INVALID_INVARIANTS);
                if(name.equals("DB_UNAVAILABLE")){pg=database(work.resolve("database"),databasePort);}
                check(before.equals(snapshot(url)),"Rejected startup changed business, queue, audit or action rows");
                check(calls.get()==0,"Rejected startup performed KYC execution");
                result.put("exitCode",subject.exitValue());result.put("startupProbes",probes);result.put("noScheduledClaim",true);
                result.put("refusalFingerprint",fingerprint(snapshot(url)));
                result.put("livenessStatus","Process exited; no live endpoint claimed");result.put("readinessStatus","Never observed ready");
                // Explicit new process with the original known-valid config. Never edit subjectOptions.
                result.put("repair","Explicit new process with original valid configuration/resource loader and restored owned database");
                checkpoint(Stage.RECOVERY_READINESS);
                int recoveryPort=freePort();Process recovery=launch(work,"recovery","NONE",base,recoveryPort);
                awaitHealth(recovery,recoveryPort,true);checkpoint(Stage.RECOVERY_CLAIM);awaitClaim(url,preparedWorkflowId,calls,recovery);stop(recovery);
                result.put("recovery","New valid process ready; queued job reached scheduled KYC execution");
            }
            checkpoint(Stage.FINAL_INVARIANTS);
            stop(subject);check("0".equals(scalar(url,"SELECT count(*) FROM mock_payment")),"Startup tests unexpectedly paid");
            var finalRows=snapshot(url);
            for(String table:List.of("demo_auth_registry","demo_token"))
                check(originalAuth.get(table).equals(finalRows.get(table)),"Startup/recovery altered durable credential authority");
            result.put("credentialAuthorityPreservedAcrossStartup",true);
            result.put("kycHttpCallsAfterRecoveryOrControl",calls.get());result.put("verdict","PASS");
        } catch(Exception | AssertionError failure) {
            writeDiagnostic(failure instanceof AssertionError?FailureCategory.ASSERTION_FAILED:FailureCategory.EXECUTION_FAILED);
            throw failure;
        } finally {cleanup();}
    }

    private EmbeddedPostgres database(Path directory,int port)throws Exception {
        var value=EmbeddedPostgres.builder().setDataDirectory(directory).setCleanDataDirectory(false).setRegisterShutdownHook(false)
            .setPort(port).setServerConfig("listen_addresses","127.0.0.1").setServerConfig("unix_socket_directories","").start();
        databases.add(value.getProcess());ports.add(value.getPort());return value;
    }
    private Process launch(Path work,String phase,String fault,List<String> options,int port)throws Exception {
        var actual=new ArrayList<>(options);actual.add("--server.port="+port);ports.add(port);
        Path invalid=work.resolve("invalid-policy.json");
        try(var source=StartupAdmissionHarness.class.getClassLoader().getResourceAsStream("config/demo_policy.json")) {
            var invalidPolicy=JSON.readValue(Objects.requireNonNull(source),Map.class);
            invalidPolicy.put("automaticRiskLimit",0);Files.writeString(invalid,JSON.writeValueAsString(invalidPolicy));
        }
        Path config=work.resolve(phase+"-config.json");Files.writeString(config,JSON.writeValueAsString(Map.of("options",actual,"fault",fault,
            "invalidPolicy",invalid.toString(),"started",work.resolve(phase+".started").toString())));privateFile(config);
        var builder=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin","java").toString(),"-cp",System.getProperty("java.class.path"),StartupAdmissionServer.class.getName(),config.toString());
        builder.environment().keySet().removeIf(key->key.startsWith("FUSE_") || key.startsWith("SPRING_") || key.endsWith("_API_KEY") ||
            key.startsWith("OPENAI_") || key.startsWith("ANTHROPIC_") || Set.of("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","PORT").contains(key));
        Process process=builder.redirectErrorStream(true).redirectOutput(work.resolve(phase+".log").toFile()).start();children.add(process);startupMarkers.put(process,work.resolve(phase+".started"));return process;
    }
    private static void replace(List<String> options,String name,String value){options.removeIf(s->s.startsWith("--"+name+"="));options.add("--"+name+"="+value);}
    private static void privateFile(Path path)throws Exception{Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------"));}
    private static int freePort()throws Exception{try(var socket=new ServerSocket(0,0,InetAddress.getByName("127.0.0.1"))){return socket.getLocalPort();}}
    private record HttpResult(int status,Map<?,?> body){}
    private static HttpResult send(HttpRequest request)throws Exception {
        try {var response=HTTP.send(request,HttpResponse.BodyHandlers.ofString());
            Map<?,?> body;try{body=JSON.readValue(response.body(),Map.class);}catch(Exception nonJson){body=Map.of();}
            return new HttpResult(response.statusCode(),body);
        }catch(java.io.IOException unavailable){return new HttpResult(0,Map.of());}
    }
    private static HttpResult get(int port,String path)throws Exception{return send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+path)).timeout(Duration.ofSeconds(2)).GET().build());}
    private static HttpResult post(int port,String token,UUID action,String customer)throws Exception {
        return send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+"/api/v1/workflows")).timeout(Duration.ofSeconds(2))
            .header("Authorization","Bearer "+token).header("Idempotency-Key",action.toString()).header("Content-Type","application/json")
            .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(Map.of("businessReference","APP-DEMO-"+customer+"-001",
                "customerId","customer-"+customer,"amountKrw",1000000,"payoutAccountId","00000000-0000-4000-8000-000000000"+customer)))).build());
    }
    private void awaitHealth(Process process,int port,boolean ready)throws Exception {
        long until=System.nanoTime()+Duration.ofSeconds(65).toNanos();
        while(System.nanoTime()<until){check(process.isAlive(),"Child exited before expected health state");HttpResult r=get(port,"/actuator/health/readiness");
            Path marker=startupMarkers.get(process);
            if(Files.exists(marker) && (process.pid()+":"+port).equals(Files.readString(marker)) &&
                r.status==(ready?200:503) && (ready?"UP":"DOWN").equals(r.body.get("status")))return;Thread.sleep(100);}
        throw new AssertionError("Expected readiness not reached");
    }
    static UUID preparedWorkflowId(Map<?,?> response) {
        Object value=response.get("workflowId");
        check(value instanceof String,"Preparation response lacks a workflow UUID");
        String text=(String)value;
        UUID workflowId;
        try {workflowId=UUID.fromString(text);}
        catch(IllegalArgumentException invalid){throw new AssertionError("Preparation response has an invalid workflow UUID",invalid);}
        check(workflowId.toString().equalsIgnoreCase(text),"Preparation response has a noncanonical workflow UUID");
        return workflowId;
    }
    static boolean workflowAwaitingApproval(String url,UUID workflowId)throws SQLException {
        try(var c=DriverManager.getConnection(url,"postgres","");
            var s=c.prepareStatement("SELECT EXISTS (SELECT 1 FROM workflow WHERE id=? AND state='WAIT_APPROVAL')")) {
            s.setObject(1,Objects.requireNonNull(workflowId));
            try(var r=s.executeQuery()){r.next();return r.getBoolean(1);}
        }
    }
    private static void awaitClaim(String url,UUID workflowId,AtomicInteger calls,Process process)throws Exception {
        long until=System.nanoTime()+Duration.ofSeconds(20).toNanos();
        while(System.nanoTime()<until){check(process.isAlive(),"Recovery child exited");
            if(calls.get()>0 && workflowAwaitingApproval(url,workflowId))return;Thread.sleep(100);}
        throw new AssertionError("Actual scheduler and synthetic replay did not reach WAIT_APPROVAL after readiness recovery");
    }
    private static Map<String,List<String>> snapshot(String url)throws Exception {
        var result=new TreeMap<String,List<String>>();
        try(var c=DriverManager.getConnection(url,"postgres","")) {
            c.setAutoCommit(false);c.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);c.setReadOnly(true);
            var tables=new ArrayList<String>();try(var s=c.createStatement();var r=s.executeQuery("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name")){while(r.next())tables.add(r.getString(1));}
            check(tables.containsAll(List.of("demo_auth_registry","demo_token","workflow_job","action_request","mock_payment","risk_ledger")),"Snapshot lacks business tables");
            for(String table:tables){var rows=new ArrayList<String>();try(var s=c.createStatement();var r=s.executeQuery("SELECT to_jsonb(t)::text FROM public.\""+table.replace("\"","\"\"")+"\" t ORDER BY to_jsonb(t)::text")){while(r.next())rows.add(r.getString(1));}result.put(table,rows);}c.commit();
        }return result;
    }
    private static String fingerprint(Object value)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(JSON.writeValueAsBytes(value)));}
    private static String scalar(String url,String query)throws Exception{try(var c=DriverManager.getConnection(url,"postgres","");var s=c.createStatement();var r=s.executeQuery(query)){r.next();return r.getString(1);}}
    private static void sql(String url,String query)throws Exception{try(var c=DriverManager.getConnection(url,"postgres","");var s=c.createStatement()){s.execute(query);}}
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    private static void stop(Process p){if(p.isAlive()){p.destroy();try{if(!p.waitFor(8,TimeUnit.SECONDS)){p.destroyForcibly();p.waitFor(5,TimeUnit.SECONDS);}}catch(InterruptedException e){p.destroyForcibly();Thread.currentThread().interrupt();}}}
    private synchronized void cleanup(){for(Process p:children)stop(p);if(agent!=null){agent.stop(0);agent=null;}if(agentExecutor!=null){agentExecutor.shutdownNow();agentExecutor=null;}
        if(pg!=null){try{pg.close();}catch(Exception failure){System.err.println("Owned database cleanup failed");}pg=null;}for(Process p:databases)stop(p);}
    private static boolean portOpen(int port){try(var s=new Socket()){s.connect(new InetSocketAddress("127.0.0.1",port),200);return true;}catch(Exception closed){return false;}}
    private void writeReport(boolean passed)throws Exception {
        boolean cleaned=children.stream().noneMatch(Process::isAlive)&&databases.stream().noneMatch(Process::isAlive)&&ports.stream().noneMatch(StartupAdmissionHarness::portOpen);
        var output=new LinkedHashMap<String,Object>();output.put("schemaVersion","FUSE-STARTUP-ADMISSION-1");output.put("status",passed&&cleaned?"PASS":"INCOMPLETE_OR_FAILED");
        output.put("originalBranches",List.of("SC-T09-B05","SC-T09-B08","SC-T19-B08","ordinaryprofileSC-T02-B08"));
        output.put("resultsSource","REAL_POSTGRES_CHILD_JVM_STARTUP");output.put("syntheticModelOutputs",true);output.put("liveRobustnessMeasured",false);
        output.put("plannedScenarioCount",CASES.size());output.put("passedScenarioCount",results.stream().filter(r->"PASS".equals(r.get("verdict"))).count());output.put("scenarios",results);output.put("cleanupVerified",cleaned);
        output.put("limitations",List.of("Bounded startup observation, not proof against all future faults", "REPLAY is a loopback synthetic HTTP fixture, not external-provider robustness", "Missing/invalid policy injection uses test-only resource loader; production beans are unchanged"));
        Files.createDirectories(report.getParent());Files.writeString(report,JSON.writerWithDefaultPrettyPrinter().writeValueAsString(output)+"\n");check(!passed||cleaned,"Owned process or port leaked");
    }
}
