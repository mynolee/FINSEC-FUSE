package com.finsec.fuse.experiments;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.workflow.KycContract;
import java.util.Map;

/** Immutable model response captured once, before either independent arm executes. */
public record ExperimentModelCapture(KycContract.Response response,String modelMode,String promptHash,String modelOutputHash) {
    public ExperimentModelCapture {
        if(response==null || !"LIVE".equals(modelMode) || promptHash==null || !promptHash.matches("[0-9a-f]{64}") ||
                modelOutputHash==null || !modelOutputHash.matches("[0-9a-f]{64}"))
            throw new IllegalArgumentException("Invalid LIVE capture");
    }
    public void validate(KycContract.Input input,Json json) {
        if(!response.boundTo(input) || !modelOutputHash.equals(json.hash(ExperimentRegistry.sorted(proposal(json)))))
            throw new IllegalArgumentException("Capture binding or output hash mismatch");
    }
    public Map<String,Object> proposal(Json json){return json.map(json.write(response.proposal()));}
    public Map<String,Object> trace(Json json) {
        return Json.ordered("modelMode",modelMode,"model",response.modelMetadata().model(),"promptVersion",response.modelMetadata().promptVersion(),
            "promptHash",promptHash,"modelOutputHash",modelOutputHash,"inputSnapshotHash",response.inputSnapshotHash(),
            "modelOutput",proposal(json),"captureRequestId",response.requestId(),"captureRunId",response.runId(),
            "bindingNote","One captured proposal is rebound to each isolated arm by the trusted experiment harness.");
    }
}
