package com.finsec.fuse.quarantine;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.persistence.Db;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

/** Query-shape/serialization tests; real eligibility and arithmetic are covered by PostgreSQL IT. */
class ImpactGraphPotentialAmountTest {
    @Test void countAndExactAmountUseOneDeduplicatedCurrentStatePopulation() {
        var db=new AggregateDb(3L,"60000001");
        UUID current=UUID.randomUUID(),historical=UUID.randomUUID(),held=UUID.randomUUID();
        var affected=new ImpactGraph.Affected(List.of(),Set.of(),Set.of(current),Set.of(current,historical),Set.of(current,held));
        var result=new ImpactGraph(db,mock(FusePolicy.class)).potentialApplications(affected);
        assertEquals(Map.of("applicationCount",3L,"totalAmountKrw","60000001","currency","KRW"),result);
        assertEquals(1,db.calls);
        assertTrue(db.sql.contains("select distinct a.id,a.amount_krw"));
        assertTrue(db.sql.contains("count(*) as application_count,coalesce(sum(amount_krw),0)::text"));
        assertTrue(db.sql.endsWith("from eligible_applications"));
        assertTrue(db.sql.contains("w.state in ('KYC_PENDING','KYC_VALIDATED','REVIEW_READY','WAIT_APPROVAL','APPROVED','PAYMENT_RESERVED','BLOCKED','ON_HOLD')"));
        assertFalse(db.sql.contains("application_registry"));
        assertFalse(db.sql.contains("customer_id"));
        assertFalse(db.sql.contains("max_amount"));
        var expected=new TreeSet<>(List.of(current.toString(),historical.toString(),held.toString()));
        assertArrayEquals(new Object[]{"{"+String.join(",",expected)+"}"},db.arguments);
    }

    @Test void emptyScopeStillReturnsKnownZeroAndCurrencyFromTheSameAggregate() {
        var db=new AggregateDb(0L,"0");
        var result=new ImpactGraph(db,mock(FusePolicy.class)).potentialApplications(
            new ImpactGraph.Affected(List.of(),Set.of(),Set.of(),Set.of(),Set.of()));
        assertEquals(Map.of("applicationCount",0L,"totalAmountKrw","0","currency","KRW"),result);
        assertEquals(1,db.calls);
        assertArrayEquals(new Object[]{"{}"},db.arguments);
    }

    @Test void arbitraryPrecisionAggregateIsNeverNarrowedToLongOrFloatingPoint() {
        // Above Long.MAX_VALUE as well as JavaScript's safe integer bound.
        String total="9223372036854775808";
        var db=new AggregateDb(184467440738L,total);
        var result=new ImpactGraph(db,mock(FusePolicy.class)).potentialApplications(
            new ImpactGraph.Affected(List.of(),Set.of(),Set.of(UUID.randomUUID()),Set.of(),Set.of()));
        assertInstanceOf(String.class,result.get("totalAmountKrw"));
        assertEquals(total,result.get("totalAmountKrw"));
        assertEquals(184467440738L,result.get("applicationCount"));
    }

    private static final class AggregateDb extends Db {
        private final Map<String,Object> aggregate;
        private String sql;private Object[] arguments;private int calls;
        AggregateDb(long count,String total) {
            super(mock(JdbcTemplate.class));
            aggregate=Map.of("application_count",count,"total_amount_krw",total);
        }
        @Override public Map<String,Object> required(String query,Object... args) {
            calls++;sql=query;arguments=args;return aggregate;
        }
    }
}
