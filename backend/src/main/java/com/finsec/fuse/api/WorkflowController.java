package com.finsec.fuse.api;

import com.finsec.fuse.auth.ActorResolver;
import com.finsec.fuse.workflow.*;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
@RequestMapping("/api/v1/workflows")
public class WorkflowController {
    private final ActorResolver actors;private final WorkflowService workflows;private final WorkflowQueryService queries;
    public WorkflowController(ActorResolver actors,WorkflowService workflows,WorkflowQueryService queries) {
        this.actors=actors;this.workflows=workflows;this.queries=queries;
    }
    @PostMapping
    public ResponseEntity<Map<String,Object>> start(@RequestHeader("Idempotency-Key") UUID actionId,@Valid @RequestBody StartWorkflowRequest request) {
        return ResponseEntity.accepted().body(workflows.start(actors.current(),actionId,request));
    }
    @GetMapping public Map<String,Object> list(@RequestParam(required=false) String state,@RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="20") int size) {
        return queries.list(actors.current(),state,page,size);
    }
    @GetMapping("/{id}") public Map<String,Object> detail(@PathVariable UUID id){return queries.detail(actors.current(),id);}
    @GetMapping("/{id}/trace") public Map<String,Object> trace(@PathVariable UUID id){return queries.trace(actors.current(),id);}
}
