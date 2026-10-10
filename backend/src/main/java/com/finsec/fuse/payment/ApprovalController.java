package com.finsec.fuse.payment;

import com.finsec.fuse.auth.ActorResolver;
import jakarta.validation.Valid;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/workflows/{workflowId}")
public class ApprovalController {
    private final ApprovalService approvals; private final ActorResolver actors;
    public ApprovalController(ApprovalService approvals,ActorResolver actors) {this.approvals=approvals;this.actors=actors;}
    @GetMapping("/approval-preview")
    public Map<String,Object> preview(@PathVariable UUID workflowId) {return approvals.preview(actors.current(),workflowId);}
    @PostMapping("/approvals") @ResponseStatus(HttpStatus.CREATED)
    public Map<String,Object> approve(@PathVariable UUID workflowId,@RequestHeader("Idempotency-Key") UUID actionId,@Valid @RequestBody ApprovalRequest request) {
        return approvals.decide(actors.current(),workflowId,actionId,request);
    }
}
