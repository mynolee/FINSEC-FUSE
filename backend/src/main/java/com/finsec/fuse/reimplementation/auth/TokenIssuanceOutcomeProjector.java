package com.finsec.fuse.reimplementation.auth;

/** Pure explicit evidence projection only; no issuance, IO or operating authority. */
public final class TokenIssuanceOutcomeProjector {
    private TokenIssuanceOutcomeProjector() { }

    public enum StorageEvidence {
        NOT_ATTEMPTED, REFUSED_BEFORE_WRITE, INSERT_CONFIRMED, COMMIT_UNCONFIRMED,
        ROLLBACK_CONFIRMED, STORAGE_FAILURE_UNCLASSIFIED
    }
    public enum Delivery { NOT_ATTEMPTED, COMPLETE, FAILED, UNKNOWN }
    public enum Cleanup { NOT_APPLICABLE, CONFIRMED, UNKNOWN }
    public enum Status {
        NOT_ISSUED, REFUSED, INSERT_AND_DELIVERY_CONFIRMED, DELIVERY_UNCONFIRMED,
        INSERT_CONFIRMED_DELIVERY_NOT_ATTEMPTED, COMMIT_UNCONFIRMED,
        FAILED_ROLLED_BACK, STORAGE_RESULT_UNKNOWN
    }
    public enum CurrentRowState { UNKNOWN }

    public record Input(StorageEvidence storage, Delivery delivery, Cleanup cleanup) {
        public Input {
            if (storage == null || delivery == null || cleanup == null) throw invalid();
            boolean noWrite = storage == StorageEvidence.NOT_ATTEMPTED
                    || storage == StorageEvidence.REFUSED_BEFORE_WRITE;
            if ((noWrite && cleanup != Cleanup.NOT_APPLICABLE)
                    || (!noWrite && cleanup == Cleanup.NOT_APPLICABLE)
                    || (storage != StorageEvidence.INSERT_CONFIRMED
                        && delivery != Delivery.NOT_ATTEMPTED)) throw invalid();
        }
        @Override public String toString() { return "TokenIssuanceOutcomeInput[REDACTED]"; }
    }

    /** Caller cannot construct a projection with contradictory flags or statuses. */
    public static final class Projection {
        private final Status status;
        private final StorageEvidence storage;
        private final Delivery delivery;
        private final Cleanup cleanup;
        private Projection(Status status, Input input) {
            this.status = status; this.storage = input.storage();
            this.delivery = input.delivery(); this.cleanup = input.cleanup();
        }
        public Status status() { return status; }
        public StorageEvidence storage() { return storage; }
        public Delivery delivery() { return delivery; }
        public Cleanup cleanup() { return cleanup; }
        public CurrentRowState currentRowState() { return CurrentRowState.UNKNOWN; }
        public boolean automaticRetryAllowed() { return false; }
        public boolean reissueAllowed() { return false; }
        public boolean executionAuthorityGranted() { return false; }
        @Override public String toString() { return "TokenIssuanceOutcomeProjection[REDACTED]"; }
    }

    public static Projection project(Input input) {
        if (input == null) throw invalid();
        Status status = switch (input.storage()) {
            case NOT_ATTEMPTED -> Status.NOT_ISSUED;
            case REFUSED_BEFORE_WRITE -> Status.REFUSED;
            case COMMIT_UNCONFIRMED -> Status.COMMIT_UNCONFIRMED;
            case ROLLBACK_CONFIRMED -> Status.FAILED_ROLLED_BACK;
            case STORAGE_FAILURE_UNCLASSIFIED -> Status.STORAGE_RESULT_UNKNOWN;
            case INSERT_CONFIRMED -> switch (input.delivery()) {
                case COMPLETE -> Status.INSERT_AND_DELIVERY_CONFIRMED;
                case FAILED, UNKNOWN -> Status.DELIVERY_UNCONFIRMED;
                case NOT_ATTEMPTED -> Status.INSERT_CONFIRMED_DELIVERY_NOT_ATTEMPTED;
            };
        };
        // Cleanup is orthogonal: unknown close cannot erase acknowledged commit/delivery.
        return new Projection(status, input);
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("INVALID_TOKEN_ISSUANCE_OUTCOME", null);
    }
}
