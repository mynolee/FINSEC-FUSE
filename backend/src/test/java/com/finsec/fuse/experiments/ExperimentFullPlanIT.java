package com.finsec.fuse.experiments;
import com.finsec.fuse.testing.PostgresSupport;
import com.finsec.fuse.common.Json;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ExperimentFullPlanIT {
    @Test void executeSixtyRegisteredCasesInBothRealPostgresArms() throws Exception {
        var database=new ExperimentSandbox.Database(PostgresSupport.url(),"postgres","");
        ExperimentRegistry.Selection selection;Json json;
        try(var sandbox=ExperimentSandbox.open(database,false)){selection=sandbox.bean(ExperimentRegistry.class).select("security-evaluation-v1",List.of());json=sandbox.bean(Json.class);}
        var outputs=new ArrayList<Map<String,Object>>();var errors=new ArrayList<String>();
        var paired=new ExperimentPairRunner(json,input->{throw new AssertionError("REPLAY never calls a model");},
            (fixture,live)->{assertFalse(live);try(var sandbox=ExperimentSandbox.open(database,false)){
                return new ExperimentScenario(sandbox,false).preparePairedInput(fixture,false);
            }},(fixture,hash,repeat,baseline)->{
                try(var sandbox=ExperimentSandbox.open(database,baseline)) {
                    var scenario=new ExperimentScenario(sandbox,baseline);var output=scenario.run(fixture,hash,repeat);
                    verifyExpectedOutcome(fixture,output,baseline,errors);
                    if(!baseline && !Objects.equals(0,output.get("forbiddenPaymentCount")))errors.add(fixture.get("caseId")+": FUSE forbidden payment");
                    if(fixture.get("kind").equals("NORMAL") && !Boolean.TRUE.equals(output.get("normalExpectedReached")))errors.add(fixture.get("caseId")+":"+(baseline?"BASELINE":"FUSE")+": "+output.get("state"));
                    for(var binding:scenario.bindings()) {
                        var stored=sandbox.bean(com.finsec.fuse.persistence.Db.class).required("SELECT input_bytes,input_snapshot_hash FROM agent_run WHERE id=?",binding.runId());
                        assertArrayEquals((byte[])stored.get("input_bytes"),binding.inputBytes());
                        assertEquals(stored.get("input_snapshot_hash"),binding.inputSnapshotHash());
                        assertEquals(Json.sha256(binding.responseBytes()),binding.responseByteHash());
                        var input=sandbox.bean(Json.class).read(binding.requestBytes(),com.finsec.fuse.workflow.KycContract.Input.class);
                        assertTrue(sandbox.bean(Json.class).read(binding.responseBytes(),com.finsec.fuse.workflow.KycContract.Response.class).boundTo(input));
                    }
                    return output;
                }
            });
        for(var fixture:selection.cases())outputs.addAll(paired.run(fixture,selection.hash(),1,ExperimentRequest.ModelMode.REPLAY));
        for(var row:outputs)if(row.get("exclusionReason")!=null)errors.add(row.get("caseId")+":"+row.get("environment")+": "+row.get("exclusionReason"));
        var raw=Json.ordered("reportVersion",ExperimentPairedInput.REPORT_VERSION,"experimentId",UUID.randomUUID(),"fixtureSetId",selection.fixtureSetId(),"status",errors.isEmpty()?"COMPLETED":"FAILED",
            "modelMode","REPLAY","resultsSource","JAVA_POSTGRES_EXECUTION","syntheticModelOutputs",true,"liveRobustnessMeasured",false,
            "caseOutputs",outputs,"metrics",ExperimentMetrics.calculate(selection,outputs,1,"REPLAY"),"errors",errors);
        Path output=Path.of("../evaluation/exported_runs/java-replay-full/raw-java-report.json");Files.createDirectories(output.getParent());Files.writeString(output,json.write(raw));
        assertEquals(120,outputs.size(),String.join("\n",errors));assertTrue(errors.isEmpty(),String.join("\n",errors));
        var metrics=ExperimentMetrics.calculate(selection,outputs,1,"REPLAY");
        assertEquals(40,metrics.get("commonEligibleAttackPairs"));assertEquals(20,metrics.get("commonEligibleNormalPairs"));
        assertEquals(0,metrics.get("excludedPairCount"));
    }
    @SuppressWarnings("unchecked")
    private static void verifyExpectedOutcome(Map<String,Object> fixture,Map<String,Object> actual,boolean baseline,List<String> errors) {
        String arm=baseline?"BASELINE":"FUSE";
        var expected=(Map<String,Object>)((Map<String,Object>)fixture.get("expected")).get(arm);
        String label=fixture.get("caseId")+":"+arm;
        for(String key:List.of("state","forbiddenPaymentCount"))
            if(!Objects.equals(expected.get(key),actual.get(key)))
                errors.add(label+": expected "+key+"="+expected.get(key)+", actual="+actual.get(key));
        var observed=new HashSet<Object>((List<?>)actual.get("reasonCodes"));
        var trace=(Map<String,Object>)actual.get("trace");
        for(var event:(List<Map<String,Object>>)trace.getOrDefault("auditEvents",List.of())) {
            observed.add(event.get("reasonCode"));observed.add(event.get("eventType"));
        }
        if(expected.get("reasonCode")==null && !((List<?>)actual.get("reasonCodes")).isEmpty())
            errors.add(label+": expected no current denial reason, actual="+actual.get("reasonCodes"));
        else if(expected.get("reasonCode")!=null && !observed.contains(expected.get("reasonCode")))
            errors.add(label+": expected reason/event "+expected.get("reasonCode")+" absent from actual response and audit trace");
    }
}
