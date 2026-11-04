package com.finsec.fuse.reimplementation.persistence;

/** New synthetic-only lease recommendation. Not service authorization or journal recovery. */
public final class LeaseStateModel {
    private LeaseStateModel() {}
    public enum Status { ACTIVE, COMPLETED, RECOVERY_BLOCKED }
    public enum Code { APPLIED, STALE, EXPIRED, NOT_EXPIRED, TERMINAL, OVERFLOW, UNCERTAIN_EFFECT }
    public record State(String owner, long fence, long version, long leaseUntil, Status status) {
        public State {
            LeaseStateModel.owner(owner); nonnegative(fence); nonnegative(version); nonnegative(leaseUntil);
            if (status == null) throw invalid();
        }
        @Override public String toString() { return "LeaseState[REDACTED]"; }
    }
    public record Transition(Code code, State state) {
        public Transition { if (code == null || state == null) throw invalid(); }
        @Override public String toString() { return "LeaseTransition[REDACTED]"; }
    }
    public static State create(String owner, long fence, long version, long leaseUntil) {
        return new State(owner, fence, version, leaseUntil, Status.ACTIVE);
    }
    public static Transition renew(State state, String expectedOwner, long expectedFence,
            long expectedVersion, long now, long newUntil) {
        check(state, expectedOwner, expectedFence, expectedVersion, now); nonnegative(newUntil);
        if (newUntil <= state.leaseUntil()) throw invalid();
        Transition guard = guard(state, expectedOwner, expectedFence, expectedVersion);
        if (guard != null) return guard;
        if (now >= state.leaseUntil()) return result(Code.EXPIRED, state);
        if (state.version() == Long.MAX_VALUE) return result(Code.OVERFLOW, state);
        return result(Code.APPLIED, new State(state.owner(), state.fence(), state.version()+1,
                newUntil, Status.ACTIVE));
    }
    public static Transition complete(State state, String expectedOwner, long expectedFence,
            long expectedVersion, long now) {
        check(state, expectedOwner, expectedFence, expectedVersion, now);
        Transition guard = guard(state, expectedOwner, expectedFence, expectedVersion);
        if (guard != null) return guard;
        if (now >= state.leaseUntil()) return result(Code.EXPIRED, state);
        if (state.version() == Long.MAX_VALUE) return result(Code.OVERFLOW, state);
        return result(Code.APPLIED, new State(state.owner(), state.fence(), state.version()+1,
                state.leaseUntil(), Status.COMPLETED));
    }
    public static Transition recover(State state, String expectedOwner, long expectedFence,
            long expectedVersion, long now, String newOwner, long newUntil, boolean sideEffectFree) {
        check(state, expectedOwner, expectedFence, expectedVersion, now);
        owner(newOwner); nonnegative(newUntil);
        if (newUntil <= now) throw invalid();
        Transition guard = guard(state, expectedOwner, expectedFence, expectedVersion);
        if (guard != null) return guard;
        if (now < state.leaseUntil()) return result(Code.NOT_EXPIRED, state);
        if (state.version() == Long.MAX_VALUE) return result(Code.OVERFLOW, state);
        if (!sideEffectFree) return result(Code.UNCERTAIN_EFFECT,
                new State(state.owner(), state.fence(), state.version()+1,
                        state.leaseUntil(), Status.RECOVERY_BLOCKED));
        if (state.fence() == Long.MAX_VALUE) return result(Code.OVERFLOW, state);
        return result(Code.APPLIED, new State(newOwner, state.fence()+1, state.version()+1,
                newUntil, Status.ACTIVE));
    }
    private static Transition guard(State state, String owner, long fence, long version) {
        if (!state.owner().equals(owner) || state.fence()!=fence || state.version()!=version)
            return result(Code.STALE, state);
        if (state.status()!=Status.ACTIVE) return result(Code.TERMINAL, state);
        return null;
    }
    private static void check(State state, String owner, long fence, long version, long now) {
        if (state == null) throw invalid();
        owner(owner); nonnegative(fence); nonnegative(version); nonnegative(now);
    }
    private static void owner(String value) {
        if (value == null || value.isBlank()) throw invalid();
    }
    private static void nonnegative(long value) { if (value < 0) throw invalid(); }
    private static Transition result(Code code, State state) { return new Transition(code, state); }
    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Invalid lease input");
    }
}
