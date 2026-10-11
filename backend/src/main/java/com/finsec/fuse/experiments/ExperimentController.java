package com.finsec.fuse.experiments;
import com.finsec.fuse.auth.ActorResolver;
import jakarta.validation.Valid;
import java.util.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@Profile({"demo","test"})
@ConditionalOnProperty(name="fuse.experiments.enabled",havingValue="true",matchIfMissing=true)
@RequestMapping("/api/v1/experiments")
public class ExperimentController {
    private final ExperimentService experiments;
    public ExperimentController(ExperimentService experiments){this.experiments=experiments;}
    @PostMapping public ResponseEntity<Map<String,Object>> start(@RequestHeader("Idempotency-Key") UUID action,@Valid @RequestBody ExperimentRequest request){
        return ResponseEntity.accepted().body(experiments.start(ActorResolver.current(),action,request));}
    @GetMapping("/{id}") public Map<String,Object> get(@PathVariable UUID id){return experiments.get(ActorResolver.current(),id);}
}
