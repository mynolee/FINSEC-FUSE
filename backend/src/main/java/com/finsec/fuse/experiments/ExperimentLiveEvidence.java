package com.finsec.fuse.experiments;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.JsonConfiguration;
import com.finsec.fuse.workflow.KycContract;
import java.util.*;

/** Validate persisted/imported LIVE evidence before it can enter either paired denominator. */
final class ExperimentLiveEvidence {
    private static final Json JSON=new Json(new JsonConfiguration().jsonMapper());
    private static final List<String> IDENTITY=List.of("modelMode","model","promptVersion","promptHash","modelOutputHash","inputSnapshotHash","captureRequestId","captureRunId");
    private ExperimentLiveEvidence(){}
    static String exclusion(Collection<Map<String,Object>> rows) {
        var identities=new ArrayList<List<String>>();
        for(var row:rows) {
            if(!(row.get("trace") instanceof Map<?,?> trace) || !(trace.get("modelCapture") instanceof Map<?,?> capture))return "LIVE_CAPTURE_MISSING";
            try {
                if(!"LIVE".equals(capture.get("modelMode")) || !Objects.equals(row.get("model"),capture.get("model")) ||
                    !Objects.equals(row.get("promptVersion"),capture.get("promptVersion")) || !Objects.equals(row.get("modelOutputHash"),capture.get("modelOutputHash")))return "LIVE_CAPTURE_INVALID";
                if(!(capture.get("model") instanceof String model) || model.isBlank() || model.length()>160 ||
                    !(capture.get("promptVersion") instanceof String prompt) || prompt.isBlank() || prompt.length()>100)return "LIVE_CAPTURE_INVALID";
                for(String field:List.of("promptHash","modelOutputHash","inputSnapshotHash"))
                    if(!(capture.get(field) instanceof String value) || !value.matches("[0-9a-f]{64}"))return "LIVE_CAPTURE_INVALID";
                for(String field:List.of("captureRequestId","captureRunId"))
                    if(!Objects.toString(capture.get(field),"").matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))return "LIVE_CAPTURE_INVALID";
                if(!(capture.get("modelOutput") instanceof Map<?,?> output))return "LIVE_CAPTURE_INVALID";
                var proposal=JSON.read(JSON.write(output),KycContract.Proposal.class);
                if(proposal.explanation().isEmpty() || !capture.get("modelOutputHash").equals(JSON.hash(ExperimentRegistry.sorted(output))))return "LIVE_CAPTURE_INVALID";
                identities.add(IDENTITY.stream().map(field->Objects.toString(capture.get(field),"")).toList());
            }catch(RuntimeException invalid){return "LIVE_CAPTURE_INVALID";}
        }
        return identities.stream().distinct().count()==1?null:"UNPAIRED_LIVE_CAPTURE";
    }
}
