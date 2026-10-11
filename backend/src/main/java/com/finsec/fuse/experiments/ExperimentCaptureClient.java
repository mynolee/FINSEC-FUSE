package com.finsec.fuse.experiments;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.PrivateDocuments;
import com.finsec.fuse.config.SecurityPolicy;
import com.finsec.fuse.http.InternalKycHttpClient;
import com.finsec.fuse.workflow.KycContract;
import jakarta.annotation.PreDestroy;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Fixed internal origin with bounded transport shared by evaluation and capture. */
@Component
public final class ExperimentCaptureClient implements ExperimentCaptureGateway {
    private final Json json;private final String token;private final InternalKycHttpClient client;private final SecurityPolicy policy;
    @Autowired
    public ExperimentCaptureClient(Json json,SecurityPolicy policy,@Value("${fuse.kyc-base-url:http://localhost:8001}") String baseUrl,
                                   @Value("${fuse.service-token:}") String token) {
        this.json=json;this.token=token;this.policy=policy;this.client=new InternalKycHttpClient(baseUrl,policy);
    }
    public ExperimentCaptureClient(Json json,String baseUrl,String token){this(json,InternalKycHttpClient.policy(json),baseUrl,token);}
    @Override public ExperimentModelCapture capture(KycContract.Input input) {
        if(input.documents().stream().anyMatch(document->PrivateDocuments.isMarker(document.text())))throw new CaptureFailure(PrivateDocuments.UNAVAILABLE);
        if(token==null || token.getBytes(java.nio.charset.StandardCharsets.UTF_8).length<32 ||
            token.chars().anyMatch(c->Character.isWhitespace(c)||c==','))throw new CaptureFailure("DEPENDENCY_UNAVAILABLE");
        try {
            input.validate(json,policy);
            var response=client.post("/internal/v1/kyc/captures",token,json.bytes(input));
            if(response.status()!=200) {
                String reason=response.status()==502?"MODEL_OUTPUT_INVALID":"DEPENDENCY_UNAVAILABLE";
                try {String reported=String.valueOf(json.map(response.body()).get("reasonCode"));
                    if(Set.of("MODEL_OUTPUT_INVALID","DEPENDENCY_UNAVAILABLE","LIVE_NOT_AVAILABLE",PrivateDocuments.UNAVAILABLE).contains(reported))reason=reported;
                }catch(RuntimeException ignored) { /* No provider/internal body reflection. */ }
                throw new CaptureFailure(reason);
            }
            try {var capture=json.read(InternalKycHttpClient.jsonText(response.body()),ExperimentModelCapture.class);capture.validate(input,json);return capture;}
            catch(RuntimeException invalid){throw new CaptureFailure("MODEL_OUTPUT_INVALID");}
        }catch(CaptureFailure known){throw known;}
        catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new CaptureFailure("DEPENDENCY_UNAVAILABLE");}
        catch(Exception unavailable){
            Throwable cause=unavailable;while(cause.getCause()!=null)cause=cause.getCause();
            throw new CaptureFailure(cause instanceof InternalKycHttpClient.InvalidOutput?"MODEL_OUTPUT_INVALID":"DEPENDENCY_UNAVAILABLE");
        }
    }
    @PreDestroy public void close() throws java.io.IOException {client.close();}
    public static final class CaptureFailure extends RuntimeException {
        private final String reason;
        public CaptureFailure(String reason){super(reason);this.reason=reason;}
        public String reason(){return reason;}
    }
}
