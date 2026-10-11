package com.finsec.fuse.persistence;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("test")
public final class MutableTimeSource implements TimeSource {
    private final AtomicReference<Instant> instant;
    public MutableTimeSource(@Value("${fuse.test-time:2026-10-09T04:00:00Z}") String initial) { instant=new AtomicReference<>(Instant.parse(initial)); }
    public Instant now() { return instant.get(); }
    public void set(Instant value) { instant.set(value); }
    public Instant advance(Duration duration) { return instant.updateAndGet(value->value.plus(duration)); }
}
