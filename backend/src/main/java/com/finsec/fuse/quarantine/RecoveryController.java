package com.finsec.fuse.quarantine;

import com.finsec.fuse.auth.ActorResolver;
import jakarta.validation.Valid;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/workflows")
public class RecoveryController {
    private final RecoveryService recovery;private final ActorResolver actors;
    public RecoveryController(RecoveryService recovery,ActorResolver actors) {this.recovery=recovery;this.actors=actors;}
    @PostMapping("/{workflowId}/resume") @ResponseStatus(HttpStatus.ACCEPTED)
    public Map<String,Object> resume(@PathVariable UUID workflowId,@RequestHeader("Idempotency-Key") UUID actionId,@Valid @RequestBody ResumeRequest request) {
        return recovery.resume(actors.current(),workflowId,actionId,request);
    }
}
