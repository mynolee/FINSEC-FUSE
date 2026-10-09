package com.finsec.fuse.experiments;

import com.finsec.fuse.common.*;
import com.finsec.fuse.config.JsonConfiguration;
import com.finsec.fuse.config.PrivateDocuments;
import com.finsec.fuse.workflow.KycContract;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ExperimentPairRunnerTest {
    private final Json json=new Json(new JsonConfiguration().jsonMapper());
    private final ExperimentRegistry registry=new ExperimentRegistry(json);
    private Map<String,Object> fixture(){return registry.select("mvp-security-v1",List.of("T02_MISSING_EVIDENCE")).cases().getFirst();}
    private KycContract.Input input(){var input=new KycContract.Input(UUID.randomUUID(),UUID.randomUUID(),1,UUID.randomUUID(),"customer-101","FUSE-MVP-2",null,List.of(),List.of());return input.withHash(json.hash(input.unhashed()));}
    private ExperimentModelCapture capture(KycContract.Input input,KycContract.Proposal proposal){return new ExperimentModelCapture(new KycContract.Response(input.requestId(),input.workflowId(),1,input.runId(),input.inputSnapshotHash(),proposal,new KycContract.ModelMetadata("actual-model-2026","KYC-PROMPT-1")),"LIVE","b".repeat(64),json.hash(ExperimentRegistry.sorted(json.map(json.write(proposal)))));}
    private KycContract.Proposal proposal(){return json.read(json.write(fixture().get("modelOutput")),KycContract.Proposal.class);}
    @Test void liveCapturesOncePerRepeatAndUsesSameImmutableCandidateInBothArms(){
        var calls=new AtomicInteger();var arms=new AtomicInteger();var candidates=new ArrayList<Object>();
        var fixture=fixture();var original=json.write(fixture);
        var runner=new ExperimentPairRunner(json,input->{calls.incrementAndGet();return capture(input,proposal());},(f,live)->new ExperimentPairedInput.Prepared(input(),Map.of()),(f,h,r,b)->{
            arms.incrementAndGet();candidates.add(f.get("modelOutput"));return arm(f,h);});
        for(int repeat=1;repeat<=3;repeat++){
            var outputs=runner.run(fixture,"a".repeat(64),repeat,ExperimentRequest.ModelMode.LIVE);
            assertEquals(outputs.getFirst().get("modelOutputHash"),outputs.getLast().get("modelOutputHash"));
            assertEquals("actual-model-2026",outputs.getFirst().get("model"));
            assertTrue(outputs.stream().allMatch(row->row.get("exclusionReason")==null));
            assertEquals(((Map<?,?>)outputs.getFirst().get("trace")).get("modelCapture"),((Map<?,?>)outputs.getLast().get("trace")).get("modelCapture"));
        }
        assertEquals(3,calls.get());assertEquals(6,arms.get());assertEquals(original,json.write(fixture));
        for(int i=0;i<candidates.size();i+=2)assertSame(candidates.get(i),candidates.get(i+1));
    }
    @Test void replayPreparesCanonicalInputWithoutCallingModel(){
        var inputs=new AtomicInteger();var calls=new AtomicInteger();
        var runner=new ExperimentPairRunner(json,i->{fail("No replay network calls");return null;},
            (f,live)->{assertFalse(live);inputs.incrementAndGet();return new ExperimentPairedInput.Prepared(input(),Map.of());},
            (f,h,r,b)->{calls.incrementAndGet();return arm(f,h);});
        var rows=runner.run(fixture(),"a".repeat(64),1,ExperimentRequest.ModelMode.REPLAY);
        assertEquals(1,inputs.get());assertEquals(2,calls.get());
        assertTrue(rows.stream().allMatch(row->row.get("exclusionReason")==null));
    }
    private Map<String,Object> arm(Map<String,Object> fixture,String hash) {
        var model=fixture.get("capturedModelMetadata") instanceof KycContract.ModelMetadata captured?captured:new KycContract.ModelMetadata("replay","KYC-PROMPT-1");
        return Json.ordered("trace",Map.of(),"model",model.model(),"modelOutputHash","old",
            "pairedInputVersion",ExperimentPairedInput.VERSION,"pairedInputHash",ExperimentPairedInput.hash(json,fixture,hash,
                new ExperimentPairedInput.Prepared(input(),Map.of()),fixture.get("capturedModelMetadata")==null?"REPLAY":"LIVE",model.model(),model.promptVersion(),(String)fixture.get("capturedPromptHash")));
    }
    @Test void failedInductionExcludesBothWithoutExecutingArmsOrClaimingPolicyBlock(){
        var refused=new KycContract.Proposal(KycContract.ProposalStatus.NOT_VERIFIED,List.of(),"Insufficient evidence");
        var runner=new ExperimentPairRunner(json,i->capture(i,refused),(f,live)->new ExperimentPairedInput.Prepared(input(),Map.of()),(f,h,r,b)->{fail("Induction failed");return null;});
        assertExcluded(runner.run(fixture(),"a".repeat(64),1,ExperimentRequest.ModelMode.LIVE),"INDUCTION_FAILED");
    }
    @Test void modelFailureExcludesBothWithoutSyntheticOutputHash(){
        var runner=new ExperimentPairRunner(json,i->{throw new ExperimentCaptureClient.CaptureFailure("DEPENDENCY_UNAVAILABLE");},(f,live)->new ExperimentPairedInput.Prepared(input(),Map.of()),(f,h,r,b)->{fail();return null;});
        var outputs=runner.run(fixture(),"a".repeat(64),1,ExperimentRequest.ModelMode.LIVE);assertExcluded(outputs,"DEPENDENCY_UNAVAILABLE");
        assertEquals("unavailable",outputs.getFirst().get("model"));assertEquals(json.hash(null),outputs.getFirst().get("modelOutputHash"));
    }
    @Test void missingPrivateDocumentsExcludeBothBeforeModelOrArms() {
        var runner=new ExperimentPairRunner(json,i->{fail("Private input is required before capture");return null;},
            (f,live)->{throw new PrivateDocuments.Unavailable();},(f,h,r,b)->{fail("No arm after missing private input");return null;});
        assertExcluded(runner.run(fixture(),"a".repeat(64),1,ExperimentRequest.ModelMode.LIVE),PrivateDocuments.UNAVAILABLE);
    }
    @Test void alteredBindingOrOutputHashIsRejectedInBothArms(){
        for(boolean badHash:List.of(false,true)){
            var runner=new ExperimentPairRunner(json,i->{var capture=capture(badHash?i:input(),proposal());return badHash?new ExperimentModelCapture(capture.response(),"LIVE",capture.promptHash(),"0".repeat(64)):capture;},(f,live)->new ExperimentPairedInput.Prepared(input(),Map.of()),(f,h,r,b)->{fail();return null;});
            assertExcluded(runner.run(fixture(),"a".repeat(64),1,ExperimentRequest.ModelMode.LIVE),"MODEL_OUTPUT_INVALID");
        }
    }
    @Test void requestRequiresExplicitLiveOptInAndExactlyThreeRepeats(){
        for(int count:List.of(2,3,10))assertThrows(ApiException.class,()->new ExperimentRequest("mvp-security-v1",List.of(),ExperimentRequest.Mode.PAIRED,ExperimentRequest.ModelMode.REPLAY,count).validate(true));
        for(int count:List.of(1,2,4))assertThrows(ApiException.class,()->new ExperimentRequest("mvp-security-v1",List.of(),ExperimentRequest.Mode.PAIRED,ExperimentRequest.ModelMode.LIVE,count).validate(true));
        var live=new ExperimentRequest("mvp-security-v1",List.of(),ExperimentRequest.Mode.PAIRED,ExperimentRequest.ModelMode.LIVE,3);
        assertThrows(ApiException.class,()->live.validate(false));assertDoesNotThrow(()->live.validate(true));
        assertDoesNotThrow(()->new ExperimentRequest("mvp-security-v1",List.of(),ExperimentRequest.Mode.PAIRED,ExperimentRequest.ModelMode.REPLAY,1).validate(false));
    }
    @Test void mismatchingArmDigestIsPreservedAndExcludedRatherThanReplacedWithExpectedHash() {
        var runner=new ExperimentPairRunner(json,i->{fail("No replay model call");return null;},
            (f,live)->new ExperimentPairedInput.Prepared(input(),Map.of()),(f,h,r,baseline)->{
                var row=arm(f,h);if(!baseline)row.put("pairedInputHash","c".repeat(64));return row;
            });
        var rows=runner.run(fixture(),"a".repeat(64),1,ExperimentRequest.ModelMode.REPLAY);
        assertNull(rows.getFirst().get("exclusionReason"));
        assertEquals("UNPAIRED_INPUT",rows.getLast().get("exclusionReason"));
        assertEquals("c".repeat(64),rows.getLast().get("pairedInputHash"));
        assertNotEquals("c".repeat(64),((Map<?,?>)rows.getLast().get("trace")).get("expectedPairedInputHash"));
    }
    @Test void publicExperimentRequestCannotSupplyItsOwnPairedDigest() {
        var body=Json.ordered("fixtureSetId","mvp-security-v1","caseIds",List.of(),"mode","PAIRED","modelMode","REPLAY","repeatCount",1,
            "pairedInputHash","0".repeat(64));
        assertThrows(tools.jackson.core.JacksonException.class,()->json.read(json.write(body),ExperimentRequest.class));
    }
    private static void assertExcluded(List<Map<String,Object>> rows,String reason){
        assertEquals(2,rows.size());for(var row:rows){assertEquals("ERROR",row.get("status"));assertEquals(reason,row.get("exclusionReason"));assertEquals(false,row.get("policyBlocked"));assertEquals(false,row.get("attackInduced"));}
    }
}
