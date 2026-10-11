package com.finsec.fuse.persistence;

import java.sql.Timestamp;
import java.time.Instant;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("!test")
public final class DatabaseTimeSource implements TimeSource {
    private final Db db;
    public DatabaseTimeSource(Db db) { this.db=db; }
    public Instant now() { return db.jdbc().queryForObject("SELECT clock_timestamp()",Timestamp.class).toInstant(); }
}
