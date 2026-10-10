package com.finsec.fuse.testing;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.DemoSeed;
import com.finsec.fuse.persistence.*;
import javax.sql.DataSource;
import java.time.Instant;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest(classes=FuseApplication.class,webEnvironment=SpringBootTest.WebEnvironment.MOCK)
@ActiveProfiles("test")
public abstract class FuseIntegrationTest {
    @DynamicPropertySource static void postgres(DynamicPropertyRegistry registry) { PostgresSupport.properties(registry); }
    @Autowired protected Db db;
    @Autowired protected Json json;
    @Autowired protected DataSource dataSource;
    @Autowired protected MutableTimeSource clock;
    @Autowired protected DemoSeed seed;
    @Autowired protected TransactionTemplate tx;
    @BeforeEach void resetIsolatedTestDatabase() throws Exception {
        // Only this harness's ephemeral PostgreSQL process. Never use a user-configured DB.
        try (var connection=dataSource.getConnection()) {
            if(!connection.getMetaData().getURL().equals(PostgresSupport.url()))
                throw new IllegalStateException("Refusing reset outside ephemeral test database");
        }
        db.jdbc().execute("DROP SCHEMA public CASCADE");
        db.jdbc().execute("CREATE SCHEMA public");
        Flyway.configure().dataSource(dataSource).locations("classpath:db/migration").load().migrate();
        clock.set(Instant.parse("2026-10-09T04:00:00Z"));
        seed.run(null);
    }
}
