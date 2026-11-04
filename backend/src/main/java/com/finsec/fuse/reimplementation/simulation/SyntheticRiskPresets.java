package com.finsec.fuse.reimplementation.simulation;

import java.time.Duration;

/** Explicit new synthetic demonstration inputs; never a default or production risk calibration. */
public final class SyntheticRiskPresets {
    private SyntheticRiskPresets() {}

    /** Caller must explicitly select and inject this value; creates no service or authority. */
    public static SimulationSpec.RiskTerms demonstrationV2() {
        return new SimulationSpec.RiskTerms("SYNTHETIC-DEMO-2", 1, 2, 3, 3, 3, 2, Duration.ofMinutes(5));
    }
}
