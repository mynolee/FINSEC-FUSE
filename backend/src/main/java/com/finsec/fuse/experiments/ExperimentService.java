package com.finsec.fuse.experiments;

import com.finsec.fuse.auth.*;
import com.finsec.fuse.common.*;
import com.finsec.fuse.persistence.*;
import jakarta.annotation.PreDestroy;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Profile;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.*;
import static com.finsec.fuse.persistence.Db.*;

@Service
@Profile({"demo","test"})
@ConditionalOnProperty(name="fuse.experiments.enabled",havingValue="true",matchIfMissing=true)
public class ExperimentService {
    private final Db db; private final Json json; private final ActionRequests actions;
    private final ExperimentRegistry registry; private final TransactionTemplate tx; private final Environment environment; private final ExperimentCaptureGateway captureGateway;
    private final ExecutorService executor=Executors.newSingleThreadExecutor(r->{
        var thread=new Thread(r,"fuse-isolated-experiments");thread.setDaemon(true);return thread;});
    public ExperimentService(Db db,Json json,ActionRequests actions,ExperimentRegistry registry,TransactionTemplate tx,Environment environment,ExperimentCaptureGateway captureGateway){
        this.db=db;this.json=json;this.actions=actions;this.registry=registry;this.tx=tx;this.environment=environment;this.captureGateway=captureGateway;
    }
    @PreDestroy public void close(){executor.shutdownNow();}
    @EventListener(ApplicationReadyEvent.class) public void interruptOldRuns(){
        db.update("UPDATE experiment SET status='INTERRUPTED',error_message='Server restarted before experiment completion',completed_at=clock_timestamp() WHERE status IN ('PENDING','RUNNING')");
    }
    @Transactional public Map<String,Object> start(Actor actor,UUID action,ExperimentRequest request){
        RoleGuard.require(actor,"DEVELOPER");var selection=registry.select(request.fixtureSetId(),request.caseIds());
        request.validate(liveEnabled());
        var database=database();db.gate();
        var replay=actions.replay(action,actor.actorId(),"START_EXPERIMENT",null,request);if(replay.isPresent())return replay.get();
        if(integer(db.required("SELECT count(*) AS n FROM experiment WHERE status IN ('PENDING','RUNNING')"),"n")>=2)
            throw new ApiException(429,"EXPERIMENT_BUSY","Two experiments are already queued or running.");
        UUID experiment=UUID.randomUUID();int total=selection.cases().size()*2*request.repeatCount();
        db.update("INSERT INTO experiment(id,actor_id,fixture_set_id,mode,model_mode,repeat_count,case_ids,status,total_runs,config_json) VALUES(?,?,?,'PAIRED',?,?,?::jsonb,'PENDING',?,?::jsonb)",
            experiment,actor.actorId(),request.fixtureSetId(),request.modelMode().name(),request.repeatCount(),
            json.write(selection.cases().stream().map(c->c.get("caseId")).toList()),total,
            json.write(Json.ordered("reportVersion",ExperimentPairedInput.REPORT_VERSION,"pairedInputVersion",ExperimentPairedInput.VERSION,
                "fixtureHash",selection.hash(),"modelMode",request.modelMode().name(),"model",request.modelMode()==ExperimentRequest.ModelMode.REPLAY?"replay":"captured-per-pair","policyVersion","FUSE-MVP-2","mockReviewerVersion","MOCK-REVIEWER-1","syntheticModelOutputs",request.modelMode()==ExperimentRequest.ModelMode.REPLAY)));
        var response=Json.ordered("requestId",action,"workflowId",null,"generation",null,"state","PENDING","decision","ALLOW","reasonCodes",List.of(),
            "message",request.modelMode()==ExperimentRequest.ModelMode.REPLAY?"Isolated mock experiment queued; replay candidates are synthetic.":"LIVE experiment queued; one model capture per case/repeat is reused by both arms.","replayed",false,"experimentId",experiment,"status","PENDING","totalRuns",total);
        actions.save(action,actor.actorId(),"START_EXPERIMENT",null,request,response);
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization(){
            @Override public void afterCommit(){executor.submit(()->execute(experiment,selection,request.repeatCount(),request.modelMode(),database));}});
        return response;
    }
    public Map<String,Object> get(Actor actor,UUID id){
        RoleGuard.require(actor,"DEVELOPER");var record=db.required("SELECT * FROM experiment WHERE id=?",id);
        if(!actor.actorId().equals(string(record,"actor_id")))throw new ApiException(404,"NOT_FOUND","Experiment not found.");
        var results=results(id);
        @SuppressWarnings("unchecked") var planned=(List<String>)json.read(string(record,"case_ids"),List.class);
        var selection=registry.select(string(record,"fixture_set_id"),planned);
        // Recompute with current provenance rules; legacy stored metrics cannot regain eligibility.
        Object metrics=ExperimentMetrics.calculate(selection,results,integer(record,"repeat_count"),string(record,"model_mode"));
        var configuration=json.map(string(record,"config_json"));
        boolean live="LIVE".equals(string(record,"model_mode"));
        @SuppressWarnings("unchecked") var measured=(Map<String,Object>)metrics;
        boolean liveMeasured=live && "COMPLETED".equals(string(record,"status")) && ((Number)measured.get("commonEligibleAttackPairs")).intValue()>0;
        return Json.ordered("reportVersion",configuration.getOrDefault("reportVersion","FUSE-EVALUATION-1"),
            "experimentId",id,"status",string(record,"status"),"fixtureSetId",string(record,"fixture_set_id"),"modelMode",string(record,"model_mode"),
            "resultsSource","JAVA_POSTGRES_EXECUTION","syntheticModelOutputs",!live,"liveRobustnessMeasured",liveMeasured,
            "totalRuns",integer(record,"total_runs"),"completedRuns",integer(record,"completed_runs"),
            "progress",Json.ordered("completed",integer(record,"completed_runs"),"total",integer(record,"total_runs")),"caseOutputs",results,"metrics",metrics,
            "limitations",List.of(live?"LIVE outputs are captured once per pair; non-RAG perturbations remain registered test-harness scenarios, not model-generated attacks.":"Synthetic candidate replay is not live LLM robustness.",
                "Baseline removes independent evidence, delegation validation, risk limits and lineage quarantine; shared authentication, exact employee approval, mock accounting and idempotency remain.",
                "Unsupported injection pairs are excluded, never reported as policy success.","Mock payment only; no real money."));
    }
    private boolean liveEnabled(){return environment.getProperty("FUSE_EXPERIMENT_LIVE_ENABLED",Boolean.class,
        environment.getProperty("fuse.experiments.live-enabled",Boolean.class,false));}
    private ExperimentSandbox.Database database(){
        String url=environment.getProperty("FUSE_EXPERIMENT_DB_URL",environment.getProperty("fuse.experiment-db-url",""));
        String username=environment.getProperty("FUSE_EXPERIMENT_DB_USERNAME",environment.getProperty("fuse.experiment-db-username",""));
        String password=environment.getProperty("FUSE_EXPERIMENT_DB_PASSWORD",environment.getProperty("fuse.experiment-db-password",""));
        String workflow=environment.getProperty("spring.datasource.url","");
        if(url.isBlank() || username.isBlank() || !url.startsWith("jdbc:postgresql:") || url.split("\\?",2)[0].equals(workflow.split("\\?",2)[0]))
            throw new ApiException(503,"EXPERIMENT_DATABASE_REQUIRED","A separate experiment PostgreSQL database and owner account are required.");
        return new ExperimentSandbox.Database(url,username,password);
    }
    private List<Map<String,Object>> results(UUID id){return db.query("SELECT output_json FROM experiment_case_result WHERE experiment_id=? ORDER BY case_id,repeat_index,environment",id).stream().map(r->json.map(string(r,"output_json"))).toList();}
    private void execute(UUID experiment,ExperimentRegistry.Selection selection,int repeats,ExperimentRequest.ModelMode mode,ExperimentSandbox.Database database){
        var privateBindings=new HashMap<String,List<ExperimentArmBinding>>();
        var pairs=new ExperimentPairRunner(json,captureGateway,(fixture,live)->{
            try(var sandbox=ExperimentSandbox.open(database,false)){
                return new ExperimentScenario(sandbox,false).preparePairedInput(fixture,live);
            }
        },(fixture,hash,repeat,baseline)->{
            try(var sandbox=ExperimentSandbox.open(database,baseline)){
                var scenario=new ExperimentScenario(sandbox,baseline);
                try {return scenario.run(fixture,hash,repeat);}
                finally {privateBindings.put(fixture.get("caseId")+":"+repeat+":"+(baseline?"BASELINE":"FUSE"),scenario.bindings());}
            }
        });
        try {
            db.update("UPDATE experiment SET status='RUNNING' WHERE id=?",experiment);
            for(var fixture:selection.cases())for(int repeat=1;repeat<=repeats;repeat++){
                if(Thread.currentThread().isInterrupted())throw new InterruptedException();
                var outputs=pairs.run(fixture,selection.hash(),repeat,mode);
                if(Thread.currentThread().isInterrupted())throw new InterruptedException();
                int iteration=repeat;
                // Store the pair atomically: interrupted capture/arm execution cannot leave a misleading half-pair.
                tx.executeWithoutResult(status->{
                    for(var captured:outputs) {
                        var retained=privateBindings.getOrDefault(bindingKey(captured),List.of());
                        if(!retained.isEmpty() && "ERROR".equals(captured.get("status"))) {
                            @SuppressWarnings("unchecked") var trace=new LinkedHashMap<>((Map<String,Object>)captured.get("trace"));
                            trace.put("armBindings",retained.stream().map(ExperimentArmBinding::trace).toList());captured.put("trace",trace);
                            captured.put("inputSnapshotHash",retained.getFirst().inputSnapshotHash());captured.put("responseByteHash",retained.getFirst().responseByteHash());
                        }
                        UUID caseResultId=UUID.randomUUID();
                        db.update("INSERT INTO experiment_case_result(id,experiment_id,case_id,environment,repeat_index,status,fixture_hash,model_version,policy_version,mock_reviewer_version,output_json,excluded_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?::jsonb,?)",
                            caseResultId,experiment,fixture.get("caseId"),captured.get("environment"),iteration,captured.get("status"),selection.hash(),captured.get("model"),"FUSE-MVP-2","MOCK-REVIEWER-1",json.write(captured),captured.get("exclusionReason"));
                        for(var binding:retained)
                            db.update("INSERT INTO experiment_arm_binding(id,case_result_id,request_id,workflow_id,run_id,generation,input_bytes,request_bytes,response_bytes,input_snapshot_hash,request_byte_hash,response_byte_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                                binding.id(),caseResultId,binding.requestId(),binding.workflowId(),binding.runId(),binding.generation(),
                                binding.inputBytes(),binding.requestBytes(),binding.responseBytes(),binding.inputSnapshotHash(),binding.requestByteHash(),binding.responseByteHash());
                    }
                    db.update("UPDATE experiment SET completed_runs=completed_runs+2 WHERE id=?",experiment);
                });
                outputs.forEach(output->privateBindings.remove(bindingKey(output)));
            }
            db.update("UPDATE experiment SET status='COMPLETED',metrics_json=?::jsonb,completed_at=clock_timestamp() WHERE id=?",json.write(ExperimentMetrics.calculate(selection,results(experiment),repeats,mode.name())),experiment);
        }catch(InterruptedException interrupted){Thread.currentThread().interrupt();db.update("UPDATE experiment SET status='INTERRUPTED',error_message='Experiment worker interrupted',completed_at=clock_timestamp() WHERE id=?",experiment);}
        catch(Exception failure){db.update("UPDATE experiment SET status='FAILED',error_message=?,completed_at=clock_timestamp() WHERE id=?","Experiment failed: "+failure.getClass().getSimpleName(),experiment);}
    }
    private static String bindingKey(Map<String,Object> output){return output.get("caseId")+":"+output.get("repeat")+":"+output.get("environment");}
    public Map<String,Object> error(Map<String,Object> fixture,String hash,int repeat,boolean baseline,String reason){
        return new ExperimentPairRunner(json,captureGateway,null,null).error(fixture,hash,repeat,baseline,reason,false);
    }
}
