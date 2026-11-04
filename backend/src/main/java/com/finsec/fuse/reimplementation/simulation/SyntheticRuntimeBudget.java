package com.finsec.fuse.reimplementation.simulation;

import java.math.BigInteger;
import java.time.Duration;

/** Explicit synthetic budget inputs and arithmetic only; does not enforce time or create workers. */
public record SyntheticRuntimeBudget(Duration providerBudget, Duration leaseBudget,
                                     Duration heartbeatInterval, Duration pairBudget, Duration overallCap) {
    private static final BigInteger NANOS_PER_SECOND = BigInteger.valueOf(1_000_000_000L);

    public SyntheticRuntimeBudget {
        requirePositive(providerBudget); requirePositive(leaseBudget); requirePositive(heartbeatInterval);
        requirePositive(pairBudget); requirePositive(overallCap);
    }

    /** Explicit caller choice; no default service attachment, clock, scheduling or authority. */
    public static SyntheticRuntimeBudget demonstrationV1() {
        return new SyntheticRuntimeBudget(Duration.ofSeconds(5), Duration.ofSeconds(10),
                Duration.ofSeconds(2), Duration.ofSeconds(15), Duration.ofSeconds(300));
    }

    /** min(overallCap, pairBudget * plannedPairs), without overflow or loss of nanosecond precision. */
    public Duration overallBudget(long plannedPairs) {
        if (plannedPairs < 1) throw new IllegalArgumentException("Positive synthetic pair count required");
        BigInteger total = nanos(pairBudget).multiply(BigInteger.valueOf(plannedPairs));
        BigInteger bounded = total.min(nanos(overallCap));
        BigInteger[] parts = bounded.divideAndRemainder(NANOS_PER_SECOND);
        return Duration.ofSeconds(parts[0].longValueExact(), parts[1].longValueExact());
    }

    private static BigInteger nanos(Duration value) {
        return BigInteger.valueOf(value.getSeconds()).multiply(NANOS_PER_SECOND)
                .add(BigInteger.valueOf(value.getNano()));
    }

    private static void requirePositive(Duration value) {
        if (value == null || value.isZero() || value.isNegative())
            throw new IllegalArgumentException("Positive explicit synthetic duration required");
    }
}
