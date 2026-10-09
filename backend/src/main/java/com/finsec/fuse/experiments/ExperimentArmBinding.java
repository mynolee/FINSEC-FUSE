package com.finsec.fuse.experiments;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.workflow.KycContract;
import java.util.Map;
import java.util.UUID;

/** Private byte evidence is persisted separately and is never serialized in an exported report. */
public record ExperimentArmBinding(UUID id,UUID requestId,UUID workflowId,UUID runId,int generation,
                                   byte[] inputBytes,byte[] requestBytes,byte[] responseBytes,
                                   String inputSnapshotHash,String requestByteHash,String responseByteHash) {
    public static ExperimentArmBinding capture(Json json,KycContract.Input input,KycContract.Response response) {
        byte[] inputBytes=json.bytes(input.unhashed()),requestBytes=json.bytes(input),responseBytes=json.bytes(response);
        if(!response.boundTo(input) || !Json.sha256(inputBytes).equals(input.inputSnapshotHash()))
            throw new IllegalArgumentException("Invalid arm binding");
        return new ExperimentArmBinding(UUID.randomUUID(),input.requestId(),input.workflowId(),input.runId(),input.generation(),
            inputBytes,requestBytes,responseBytes,input.inputSnapshotHash(),Json.sha256(requestBytes),Json.sha256(responseBytes));
    }
    public Map<String,Object> trace() {
        return Json.ordered("bindingId",id,"requestId",requestId,"workflowId",workflowId,"runId",runId,"generation",generation,
            "inputSnapshotHash",inputSnapshotHash,"requestByteHash",requestByteHash,"responseByteHash",responseByteHash,
            "bindingVerified",true);
    }
}
