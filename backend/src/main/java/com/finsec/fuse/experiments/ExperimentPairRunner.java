package com.finsec.fuse.experiments;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.PrivateDocuments;
import com.finsec.fuse.workflow.KycContract;
import java.util.*;
import java.util.function.BiFunction;

/** Capture is outside both arms and outside database transactions. Neither arm calls a model. */
public final class ExperimentPairRunner {
    @FunctionalInterface public interface ArmRunner {
        Map<String,Object> run(Map<String,Object> fixture,String hash,int repeat,boolean baseline);
    }
    private final Json json;private final ExperimentCaptureGateway gateway;
    private final BiFunction<Map<String,Object>,Boolean,ExperimentPairedInput.Prepared> inputProvider;private final ArmRunner arms;
    public ExperimentPairRunner(Json json,ExperimentCaptureGateway gateway,BiFunction<Map<String,Object>,Boolean,ExperimentPairedInput.Prepared> inputProvider,ArmRunner arms) {
        this.json=json;this.gateway=gateway;this.inputProvider=inputProvider;this.arms=arms;
    }
    public List<Map<String,Object>> run(Map<String,Object> fixture,String hash,int repeat,ExperimentRequest.ModelMode mode) {
        boolean live=mode==ExperimentRequest.ModelMode.LIVE;ExperimentModelCapture capture=null;String exclusion=null;
        Map<String,Object> pairedFixture=fixture;String pairedHash=null;
        if(!ExperimentScenario.supports(fixture))exclusion="UNSUPPORTED_SCENARIO:"+operation(fixture);
        else {
            try {
                var prepared=inputProvider.apply(fixture,live);var input=prepared.input();
                if(live) {
                    var candidate=gateway.capture(input);candidate.validate(input,json);capture=candidate;
                    pairedFixture=new LinkedHashMap<>(fixture);pairedFixture.put("modelOutput",capture.response().proposal());
                    pairedFixture.put("capturedModelMetadata",capture.response().modelMetadata());
                    pairedFixture.put("capturedPromptHash",capture.promptHash());pairedFixture.put("pairedDocuments",input.documents());
                    pairedFixture=Collections.unmodifiableMap(pairedFixture);
                    if("ATTACK".equals(fixture.get("kind")) && !matchesRegisteredPrecondition(fixture,capture.response().proposal()))exclusion="INDUCTION_FAILED";
                }
                pairedHash=ExperimentPairedInput.hash(json,fixture,hash,prepared,mode.name(),
                    live?capture.response().modelMetadata().model():"replay",live?capture.response().modelMetadata().promptVersion():"KYC-PROMPT-1",
                    live?capture.promptHash():null);
            }catch(ExperimentCaptureClient.CaptureFailure failure){exclusion=failure.reason();}
            catch(PrivateDocuments.Unavailable unavailable){exclusion=PrivateDocuments.UNAVAILABLE;}
            catch(IllegalArgumentException invalid){exclusion="MODEL_OUTPUT_INVALID";}
            catch(Exception unavailable){exclusion="CAPTURE_ERROR:"+unavailable.getClass().getSimpleName();}
        }
        var results=new ArrayList<Map<String,Object>>();
        for(boolean baseline:List.of(true,false)) {
            Map<String,Object> output;
            if(exclusion!=null)output=error(fixture,hash,repeat,baseline,exclusion,live);
            else try {output=new LinkedHashMap<>(arms.run(pairedFixture,hash,repeat,baseline));}
            catch(Exception failure){output=error(fixture,hash,repeat,baseline,"ENVIRONMENT_ERROR:"+failure.getClass().getSimpleName(),live);}
            if(capture!=null)stamp(output,capture);
            // Technical failures have no completed arm digest; preserve their root-cause exclusion.
            if(exclusion==null && !"ERROR".equals(output.get("status")) && !"ERROR".equals(output.get("decision")) &&
                    Objects.toString(output.get("exclusionReason"),"").isEmpty() &&
                    (!ExperimentPairedInput.VERSION.equals(output.get("pairedInputVersion")) ||
                    !Objects.equals(pairedHash,output.get("pairedInputHash")))) {
                output.put("exclusionReason","UNPAIRED_INPUT");
            }
            // Failures may retain a prepared pair digest, but are still excluded by status/reason.
            if(output.get("pairedInputHash")==null)output.put("pairedInputHash",pairedHash);
            output.putIfAbsent("pairedInputVersion",ExperimentPairedInput.VERSION);
            @SuppressWarnings("unchecked") var trace=new LinkedHashMap<>((Map<String,Object>)output.getOrDefault("trace",Map.of()));
            trace.put("expectedPairedInputHash",pairedHash);output.put("trace",trace);
            results.add(output);
        }
        return results;
    }
    /** The harness tests a registered perturbation only when its candidate prerequisites occurred. */
    private boolean matchesRegisteredPrecondition(Map<String,Object> fixture,KycContract.Proposal actual) {
        var expected=json.read(json.write(fixture.get("modelOutput")),KycContract.Proposal.class);
        return expected.status()==actual.status() && expected.evidenceIds().size()==actual.evidenceIds().size() &&
            new HashSet<>(expected.evidenceIds()).equals(new HashSet<>(actual.evidenceIds()));
    }
    @SuppressWarnings("unchecked") private void stamp(Map<String,Object> output,ExperimentModelCapture capture) {
        output.put("model",capture.response().modelMetadata().model());output.put("promptVersion",capture.response().modelMetadata().promptVersion());
        output.put("modelOutputHash",capture.modelOutputHash());
        var trace=new LinkedHashMap<>((Map<String,Object>)output.getOrDefault("trace",Map.of()));trace.put("modelCapture",capture.trace(json));
        trace.put("inductionRule","Registered status and evidence-ID precondition, ignoring explanation; nonmatching attack candidates exclude both arms.");
        output.put("trace",trace);
    }
    @SuppressWarnings("unchecked") private static String operation(Map<String,Object> fixture){return ((Map<String,Object>)fixture.get("injection")).get("operation").toString();}
    public Map<String,Object> error(Map<String,Object> fixture,String hash,int repeat,boolean baseline,String reason,boolean live) {
        return Json.ordered("caseId",fixture.get("caseId"),"environment",baseline?"BASELINE":"FUSE","repeat",repeat,"status","ERROR","state","ON_HOLD","decision","ERROR","reasonCodes",List.of(reason),
            "attackInduced",false,"policyBlocked",false,"forbiddenPaymentCount",0,"forbiddenPaidAmountKrw",0,"actualDownstreamDepth",0,"normalExpectedReached",null,
            "unrelatedNormalExpected",0,"unrelatedNormalCompleted",0,"securityCheckDurationMs",null,"quarantineLatencyMs",null,"trace",Map.of(),"exclusionReason",reason,
            "fixtureHash",hash,"modelOutputHash",json.hash(live?null:ExperimentRegistry.sorted(fixture.get("modelOutput"))),
            "pairedInputVersion",ExperimentPairedInput.VERSION,"pairedInputHash",null,"inputSnapshotHash",null,"responseByteHash",null,
            "model",live?"unavailable":"replay","promptVersion",live?"unavailable":"KYC-PROMPT-1","policyVersion","FUSE-MVP-2","mockReviewerVersion","MOCK-REVIEWER-1");
    }
}
