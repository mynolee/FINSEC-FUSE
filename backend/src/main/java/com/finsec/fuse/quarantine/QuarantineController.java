package com.finsec.fuse.quarantine;

import com.finsec.fuse.auth.ActorResolver;
import jakarta.validation.Valid;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
public class QuarantineController {
    private final QuarantineService quarantines;private final ActorResolver actors;
    public QuarantineController(QuarantineService quarantines,ActorResolver actors) {this.quarantines=quarantines;this.actors=actors;}
    @PostMapping("/quarantines") @ResponseStatus(HttpStatus.CREATED)
    public Map<String,Object> apply(@RequestHeader("Idempotency-Key") UUID actionId,@Valid @RequestBody QuarantineRequest request) {return quarantines.apply(actors.current(),actionId,request);}
    @PostMapping("/quarantines/{quarantineId}/release")
    public Map<String,Object> release(@PathVariable UUID quarantineId,@RequestHeader("Idempotency-Key") UUID actionId,@Valid @RequestBody ReleaseRequest request) {return quarantines.release(actors.current(),quarantineId,actionId,request);}
    @GetMapping("/incidents/{quarantineId}/impact")
    public Map<String,Object> impact(@PathVariable UUID quarantineId) {return quarantines.impact(actors.current(),quarantineId);}
}
