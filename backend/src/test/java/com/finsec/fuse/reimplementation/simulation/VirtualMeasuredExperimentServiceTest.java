package com.finsec.fuse.reimplementation.simulation;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.simulation.SimulationFixture.*;
import static com.finsec.fuse.reimplementation.simulation.VirtualExperimentMetricsProjection.*;
import static org.junit.jupiter.api.Assertions.*;

/** Explicit synthetic measurements through owned experiment producer transactions. */
final class VirtualMeasuredExperimentServiceTest {
    private static final String A="a".repeat(64), B="b".repeat(64);
    private static final ConfigBinding CONFIG=new ConfigBinding(A,"synthetic-review","synthetic-prompt","synthetic-model","synthetic-policy");
    private static final class Evaluator implements VirtualExperimentService.MeasuredPairEvaluator {
        final AtomicInteger calls=new AtomicInteger(); boolean nullFuse,badConfig,badShared,fail;
        public String mode() { return "VIRTUAL_NON_DURABLE"; }
        public List<VirtualExperimentService.MeasuredFixture> measuredFixtures() {
            return List.of(new VirtualExperimentService.MeasuredFixture("synthetic-measured",
                    List.of(new ExpectedCase("synthetic-normal",Kind.NORMAL)),CONFIG,Map.of("synthetic-normal",A),2));
        }
        public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment e,String id,int repeat,Map<String,Object> proposal) {
            throw new AssertionError("Opt-in path must use measured producer");
        }
        public VirtualExperimentService.MeasuredObservation evaluateMeasured(VirtualExperimentService.Environment e,
                String id,int repeat,Map<String,Object> proposal,String sharedHash) {
            calls.incrementAndGet();
            assertThrows(UnsupportedOperationException.class,()->proposal.put("status","synthetic-mutated"));
            if(fail)throw new IllegalStateException("synthetic evaluator diagnostic");
            var cfg=badConfig?new ConfigBinding(A,"synthetic-review","synthetic-prompt","synthetic-model","other-policy"):CONFIG;
            var arm=new MeasuredArm(id,repeat,e==VirtualExperimentService.Environment.BASELINE?Environment.BASELINE:Environment.FUSE,
                    Status.COMPLETED,Decision.WAIT_APPROVAL,false,false,0,0,0,true,0,0,null,null,null,cfg,B,
                    new ArmBinding("FUSE-PAIRED-INPUT-1",A,A,B,A));
            return new VirtualExperimentService.MeasuredObservation(
                    new VirtualExperimentService.Observation(VirtualExperimentService.Outcome.WAIT_APPROVAL,
                        VirtualExperimentService.Reason.SYNTHETIC_REVIEW),
                    nullFuse&&e==VirtualExperimentService.Environment.FUSE?null:arm,badShared?B:sharedHash);
        }
    }
    private VirtualExperimentService service(SimulationFixture f,VirtualExperimentService.PairEvaluator evaluator) {
        return new VirtualExperimentService(f.store,f.access,List.of(new VirtualExperimentService.FixtureSet("synthetic-measured",
                List.of(new VirtualExperimentService.Case("synthetic-normal",SimulationSpec.KycStatus.VERIFIED,List.of(ID_FACT,FACE_FACT))))),evaluator,f::id);
    }
    private UUID create(SimulationFixture f,VirtualExperimentService service) {
        return UUID.fromString((String)service.create(ACTOR,f.id(),new VirtualExperimentService.Plan(
                "synthetic-measured",List.of("synthetic-normal"),"PAIRED","REPLAY",1)).get("experimentId"));
    }
    private Map<?,?> metrics(Map<String,Object> row) { return (Map<?,?>)row.get("metrics"); }
    private Map<?,?> env(Map<String,Object> row,String e) { return (Map<?,?>)((Map<?,?>)metrics(row).get("environments")).get(e); }
    private long n(Object value) { return ((Number)value).longValue(); }
    private void noPrivateProof(Map<String,Object> row) {
        for(String k:List.of("measurementPlan","measurementCreateRequestId","measuredArms","measurementPairHash","measurementPairIndex"))
            assertFalse(row.containsKey(k),k);
        assertFalse(row.toString().contains("producerActionId"));
    }
    @Test void ordinaryProducerStoresActualArmsAndPublicGetReportsEligibleNullTiming() {
        var f=new SimulationFixture();var evaluator=new Evaluator();var service=service(f,evaluator);UUID id=create(f,service);
        var pending=service.get(ACTOR,id);assertEquals(1,n(metrics(pending).get("excludedPairCount")));
        var receipt=service.advance(ACTOR,f.id(),id);noPrivateProof(receipt);
        var stored=f.store.snapshot().get("virtual_experiments").get(id.toString());
        var arms=(List<?>)stored.get("measuredArms");assertEquals(2,arms.size());
        assertTrue(((Map<?,?>)arms.get(0)).containsKey("producerActionId"));
        assertTrue(((Map<?,?>)arms.get(1)).containsKey("sharedProposalHash"));
        var row=service.get(ACTOR,id);assertEquals(2,evaluator.calls.get());assertEquals("COMPLETED",row.get("status"));
        assertEquals(1,n(metrics(row).get("commonEligibleNormalPairs")));assertEquals(0,n(metrics(row).get("excludedPairCount")));
        assertNull(env(row,"BASELINE").get("meanSecurityCheckDurationMs"));assertNull(env(row,"FUSE").get("meanQuarantineLatencyMs"));
        assertEquals("VIRTUAL_SIMULATION",row.get("resultsSource"));assertEquals(false,row.get("liveRobustnessMeasured"));
        noPrivateProof(row);
    }
    @Test void leasedProducerUsesOpaquePermitAndFinalizedGlobalPairProof() {
        var f=new SimulationFixture();var evaluator=new Evaluator();var service=service(f,evaluator);UUID id=create(f,service);UUID action=f.id();
        var claim=service.claimLeased(ACTOR,action,id,"synthetic-worker",10,20);assertNotNull(claim.permit());
        var evaluated=service.evaluateLeased(ACTOR,claim.permit(),11);assertNotNull(evaluated.evaluatedPair());assertNull(evaluated.savedReceipt());
        var receipt=service.finalizeLeased(ACTOR,claim.permit(),evaluated.evaluatedPair(),12);noPrivateProof(receipt);
        var row=service.get(ACTOR,id);assertEquals(1,n(metrics(row).get("commonEligibleNormalPairs")));noPrivateProof(row);
        var replay=service.claimLeased(ACTOR,action,id,"synthetic-worker",30,40);assertNull(replay.permit());noPrivateProof(replay.receipt());
        assertEquals(2,evaluator.calls.get());
    }
    @Test void nullOneArmMeansIncompleteNotFakeNormalSuccessOrZeroDuration() {
        var f=new SimulationFixture();var evaluator=new Evaluator();evaluator.nullFuse=true;var service=service(f,evaluator);UUID id=create(f,service);
        service.advance(ACTOR,f.id(),id);var row=service.get(ACTOR,id);var m=metrics(row);
        assertEquals(0,n(m.get("commonEligibleNormalPairs")));assertEquals(1,n(m.get("excludedPairCount")));
        assertEquals("INCOMPLETE_PAIR",((Map<?,?>)((List<?>)m.get("exclusions")).get(0)).get("reason"));
        var e=env(row,"FUSE");assertEquals(1,n(e.get("normalEnvironmentFailureCount")));
        assertEquals(1,n(((Map<?,?>)e.get("normalFalseBlockRate")).get("denominator")));
        assertNull(e.get("meanSecurityCheckDurationMs"));
    }
    @Test void wrongPrecommittedConfigOrSharedProposalNeverPublishesEligibleMeasurement() {
        for(boolean configMismatch:List.of(true,false)) {
            var f=new SimulationFixture();var evaluator=new Evaluator();evaluator.badConfig=configMismatch;evaluator.badShared=!configMismatch;
            var service=service(f,evaluator);UUID id=create(f,service);service.advance(ACTOR,f.id(),id);var row=service.get(ACTOR,id);
            assertEquals(0,n(metrics(row).get("commonEligibleNormalPairs")));assertEquals(1,n(metrics(row).get("excludedPairCount")));
            assertNull(env(row,"BASELINE").get("meanSecurityCheckDurationMs"));noPrivateProof(row);
        }
    }
    @Test void evaluatorFailureReplaysStoredProgressWithoutRetryOrFabricatedArms() {
        var f=new SimulationFixture();var evaluator=new Evaluator();evaluator.fail=true;var service=service(f,evaluator);UUID id=create(f,service);UUID action=f.id();
        service.advance(ACTOR,action,id);int calls=evaluator.calls.get();service.advance(ACTOR,action,id);
        assertEquals(calls,evaluator.calls.get());assertEquals(2,calls);var row=service.get(ACTOR,id);
        assertEquals(0,n(metrics(row).get("commonEligibleNormalPairs")));assertNull(env(row,"FUSE").get("meanSecurityCheckDurationMs"));
        assertFalse(row.toString().contains("synthetic evaluator diagnostic"));noPrivateProof(row);
    }
    @Test void legacyEvaluatorRemainsCountOnlyWithoutInventedMeasurementFields() {
        var f=new SimulationFixture();var calls=new AtomicInteger();var service=service(f,new VirtualExperimentService.PairEvaluator() {
            public String mode() { return "VIRTUAL_NON_DURABLE"; }
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment e,String id,int repeat,Map<String,Object> proposal) {
                calls.incrementAndGet();return new VirtualExperimentService.Observation(VirtualExperimentService.Outcome.WAIT_APPROVAL,
                        VirtualExperimentService.Reason.SYNTHETIC_REVIEW);
            }
        });UUID id=create(f,service);service.advance(ACTOR,f.id(),id);var row=service.get(ACTOR,id);
        assertEquals(2,calls.get());assertFalse(metrics(row).containsKey("environments"));assertFalse(metrics(row).containsKey("plannedNormals"));noPrivateProof(row);
    }
}
