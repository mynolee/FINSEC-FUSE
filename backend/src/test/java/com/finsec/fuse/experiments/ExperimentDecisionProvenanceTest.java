package com.finsec.fuse.experiments;

import com.finsec.fuse.common.*;
import com.finsec.fuse.policy.PolicyException;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import static org.junit.jupiter.api.Assertions.*;

class ExperimentDecisionProvenanceTest {
    @Test void serviceDecisionIsPreservedIndependentlyOfReason() {
        for(String decision:List.of("WAIT_APPROVAL","DENY","ALLOW","ERROR")) {
            var response=Json.ordered("decision",decision,"reasonCodes",List.of("SYNTHETIC_REASON"));
            var outcome=ExperimentScenario.AttemptOutcome.response(response);
            assertEquals(decision,outcome.decision());assertEquals("SYNTHETIC_REASON",outcome.reason());
        }
        var accepted=ExperimentScenario.AttemptOutcome.response(Json.ordered("decision","ALLOW","reasonCodes",List.of()));
        assertEquals("ALLOW",accepted.decision());assertNull(accepted.reason());
    }
    @Test void missingDecisionCannotBeReconstructedFromReason() {
        assertThrows(IllegalStateException.class,()->ExperimentScenario.AttemptOutcome.response(Map.of("reasonCodes",List.of("APPROVAL_REQUIRED"))));
        assertThrows(IllegalStateException.class,()->ExperimentScenario.AttemptOutcome.response(Map.of("decision","" ,"reasonCodes",List.of())));
    }
    @Test void policyExceptionIsAnExplicitDenial() {
        var outcome=ExperimentScenario.AttemptOutcome.policy(new PolicyException("SCOPE_EXCEEDED"));
        assertEquals("DENY",outcome.decision());assertEquals("SCOPE_EXCEEDED",outcome.reason());
    }
    @Test void requestRejectionsMatchApiHandlerAndServerFailuresEscapeForExclusion() {
        var handler=new ApiErrorHandler();
        for(int status:List.of(400,403,409)) {
            var error=new ApiException(status,"SYNTHETIC_REQUEST_REJECTION","Synthetic request");
            var outcome=ExperimentScenario.AttemptOutcome.request(error);
            assertEquals(handler.api(error,new MockHttpServletRequest()).getBody().get("decision"),outcome.decision());
            assertEquals(error.reasonCode(),outcome.reason());
        }
        for(int status:List.of(500,503)) {
            var error=new ApiException(status,"DEPENDENCY_UNAVAILABLE","Synthetic server failure");
            assertEquals("ERROR",handler.api(error,new MockHttpServletRequest()).getBody().get("decision"));
            assertSame(error,assertThrows(ApiException.class,()->ExperimentScenario.AttemptOutcome.request(error)));
        }
    }
    @Test void technicalProbeFailuresAreExcludedByThePairRunnerRatherThanCountedAsBlocks() {
        var json=new Json(new com.finsec.fuse.config.JsonConfiguration().jsonMapper());
        var fixture=new ExperimentRegistry(json).select("mvp-security-v1",List.of("T01_NORMAL_PAYMENT")).cases().getFirst();
        var input=new com.finsec.fuse.workflow.KycContract.Input(UUID.randomUUID(),UUID.randomUUID(),1,UUID.randomUUID(),
            "customer-102","FUSE-MVP-2",null,List.of(),List.of());
        var prepared=new ExperimentPairedInput.Prepared(input.withHash(json.hash(input.unhashed())),Map.of());
        var runner=new ExperimentPairRunner(json,i->{throw new AssertionError("Replay must not call a model");},
            (f,live)->prepared,(f,h,r,baseline)->{
                ExperimentScenario.AttemptOutcome.request(new ApiException(503,"DEPENDENCY_UNAVAILABLE","Synthetic failure"));
                throw new AssertionError("Server failure must escape the scenario");
            });
        var rows=runner.run(fixture,"a".repeat(64),1,ExperimentRequest.ModelMode.REPLAY);
        assertEquals(2,rows.size());
        for(var row:rows) {
            assertEquals("ERROR",row.get("status"));assertEquals("ERROR",row.get("decision"));
            assertEquals(false,row.get("policyBlocked"));assertNotNull(row.get("exclusionReason"));
        }
    }

}
