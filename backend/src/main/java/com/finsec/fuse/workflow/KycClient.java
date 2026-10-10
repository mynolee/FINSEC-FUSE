package com.finsec.fuse.workflow;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.PrivateDocuments;
import com.finsec.fuse.config.SecurityPolicy;
import com.finsec.fuse.http.InternalKycHttpClient;
import jakarta.annotation.PreDestroy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Only this adapter crosses the Python trust boundary. No call runs under a DB transaction. */
@Component
public class KycClient implements KycGateway {
    private final InternalKycHttpClient client;
    private final String serviceToken;
    private final Json json;
    private final boolean live;
    private final SecurityPolicy policy;

    @Autowired
    public KycClient(Json json, SecurityPolicy policy, @Value("${fuse.kyc-base-url:http://localhost:8001}") String baseUrl,
                     @Value("${fuse.service-token:}") String serviceToken,
                     @Value("${fuse.kyc-mode:replay}") String mode) {
        this.json=json;this.policy=policy;this.live="live".equalsIgnoreCase(mode);this.serviceToken=serviceToken;
        this.client=new InternalKycHttpClient(baseUrl,policy);
    }
    public KycClient(Json json,String baseUrl,String token,String mode){this(json,InternalKycHttpClient.policy(json),baseUrl,token,mode);}
    public KycClient(Json json,String baseUrl,String token){this(json,baseUrl,token,"replay");}

    @Override public KycContract.Response evaluate(KycContract.Input input) {
        if(live && input.documents().stream().anyMatch(document->PrivateDocuments.isMarker(document.text())))throw new KycFailure(PrivateDocuments.UNAVAILABLE);
        if(serviceToken==null || serviceToken.getBytes(java.nio.charset.StandardCharsets.UTF_8).length<32 ||
            serviceToken.chars().anyMatch(c->Character.isWhitespace(c)||c==','))throw new KycFailure("DEPENDENCY_UNAVAILABLE");
        try {
            input.validate(json,policy);
            var response=client.post("/internal/v1/kyc/evaluations",serviceToken,json.bytes(input));
            if(response.status()!=200) {
                String reason=response.status()==502?"MODEL_OUTPUT_INVALID":"DEPENDENCY_UNAVAILABLE";
                try {String reported=String.valueOf(json.map(response.body()).get("reasonCode"));
                    if(java.util.Set.of("MODEL_OUTPUT_INVALID",PrivateDocuments.UNAVAILABLE).contains(reported))reason=reported;}
                catch(RuntimeException ignored) { /* No provider/internal body reflection. */ }
                throw new KycFailure(reason);
            }
            try {return json.read(InternalKycHttpClient.jsonText(response.body()),KycContract.Response.class);}
            catch(RuntimeException invalid){throw new KycFailure("MODEL_OUTPUT_INVALID");}
        } catch(KycFailure known){throw known;}
        catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new KycFailure("DEPENDENCY_UNAVAILABLE");}
        catch(Exception failed){
            Throwable root=failed;while(root.getCause()!=null)root=root.getCause();
            throw new KycFailure(root instanceof InternalKycHttpClient.InvalidOutput?"MODEL_OUTPUT_INVALID":"DEPENDENCY_UNAVAILABLE");
        }
    }
    @PreDestroy public void close() throws java.io.IOException {client.close();}
    public static class KycFailure extends RuntimeException {
        private final String reasonCode;
        public KycFailure(String reasonCode){super(reasonCode);this.reasonCode=reasonCode;}
        public String reasonCode(){return reasonCode;}
    }
}
