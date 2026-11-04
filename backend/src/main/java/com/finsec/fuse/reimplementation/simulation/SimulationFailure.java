package com.finsec.fuse.reimplementation.simulation;

/** Fixed public error vocabulary; never returns dependency exception messages. */
public final class SimulationFailure extends RuntimeException {
    private final int status;
    private final String code;
    private SimulationFailure(int status, String code) { super(code); this.status = status; this.code = code; }
    public int status() { return status; }
    public String code() { return code; }
    public static SimulationFailure invalid() { return new SimulationFailure(400, "INVALID_REQUEST"); }
    public static SimulationFailure forbidden() { return new SimulationFailure(403, "FORBIDDEN"); }
    public static SimulationFailure unauthenticated() { return new SimulationFailure(401, "UNAUTHENTICATED"); }
    public static SimulationFailure unavailable() { return new SimulationFailure(503, "DEPENDENCY_UNAVAILABLE"); }
}
