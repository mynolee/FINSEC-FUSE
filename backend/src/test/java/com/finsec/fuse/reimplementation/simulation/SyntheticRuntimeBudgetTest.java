package com.finsec.fuse.reimplementation.simulation;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Arithmetic examples only; no sleeps, worker execution or deadline enforcement claims. */
final class SyntheticRuntimeBudgetTest {
    @Test void explicitDemonstrationValuesAndCapBoundaryAreExact() {
        var budget = SyntheticRuntimeBudget.demonstrationV1();
        assertEquals(Duration.ofSeconds(5), budget.providerBudget());
        assertEquals(Duration.ofSeconds(10), budget.leaseBudget());
        assertEquals(Duration.ofSeconds(2), budget.heartbeatInterval());
        assertEquals(Duration.ofSeconds(15), budget.pairBudget());
        assertEquals(Duration.ofSeconds(300), budget.overallCap());
        assertEquals(Duration.ofSeconds(15), budget.overallBudget(1));
        assertEquals(Duration.ofSeconds(285), budget.overallBudget(19));
        assertEquals(Duration.ofSeconds(300), budget.overallBudget(20));
        assertEquals(Duration.ofSeconds(300), budget.overallBudget(21));
        assertEquals(Duration.ofSeconds(300), budget.overallBudget(Long.MAX_VALUE));
    }

    @Test void invalidPairCountsAreRejectedWithoutInventingAnUpperPlanLimit() {
        var budget = SyntheticRuntimeBudget.demonstrationV1();
        assertThrows(IllegalArgumentException.class, () -> budget.overallBudget(0));
        assertThrows(IllegalArgumentException.class, () -> budget.overallBudget(-1));
        assertThrows(IllegalArgumentException.class, () -> budget.overallBudget(Long.MIN_VALUE));
        assertEquals(Duration.ofSeconds(300), budget.overallBudget(1000));
    }

    @Test void everyExplicitDurationMustBePresentAndStrictlyPositive() {
        Duration valid = Duration.ofSeconds(1);
        for (int slot = 0; slot < 5; slot++) {
            for (Duration invalid : new Duration[] {null, Duration.ZERO, Duration.ofNanos(-1)}) {
                Duration[] values = {valid, valid, valid, valid, valid}; values[slot] = invalid;
                assertThrows(IllegalArgumentException.class, () -> new SyntheticRuntimeBudget(
                        values[0], values[1], values[2], values[3], values[4]));
            }
        }
    }

    @Test void fractionalDurationsPreservePrecisionAndRespectNonIntegralCap() {
        var budget = new SyntheticRuntimeBudget(Duration.ofNanos(1), Duration.ofNanos(2),
                Duration.ofNanos(1), Duration.ofNanos(150), Duration.ofNanos(499));
        assertEquals(Duration.ofNanos(450), budget.overallBudget(3));
        assertEquals(Duration.ofNanos(499), budget.overallBudget(4));
        var crossing = new SyntheticRuntimeBudget(Duration.ofSeconds(1), Duration.ofSeconds(1),
                Duration.ofSeconds(1), Duration.ofSeconds(1, 750_000_001), Duration.ofSeconds(10));
        assertEquals(Duration.ofSeconds(3, 500_000_002), crossing.overallBudget(2));
    }

    @Test void hugeDurationsDoNotOverflowBeforeCappingAndOnePairCanReachCap() {
        Duration largest = Duration.ofSeconds(Long.MAX_VALUE, 999_999_999);
        var budget = new SyntheticRuntimeBudget(Duration.ofNanos(1), Duration.ofNanos(1),
                Duration.ofNanos(1), largest, largest);
        assertEquals(largest, budget.overallBudget(1));
        assertEquals(largest, budget.overallBudget(Long.MAX_VALUE));
        var smallerCap = new SyntheticRuntimeBudget(Duration.ofNanos(1), Duration.ofNanos(1),
                Duration.ofNanos(1), largest, Duration.ofNanos(7));
        assertEquals(Duration.ofNanos(7), smallerCap.overallBudget(1));
    }
}
