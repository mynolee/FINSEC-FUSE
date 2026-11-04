package com.finsec.fuse.reimplementation.persistence;

/** Fixed, redacted failure; underlying driver exceptions are never attached.
 * Neither code is a confirmed rollback receipt or permission to retry.
 * STORAGE_UNAVAILABLE is intentionally unclassified across acquisition/read/write/cleanup.
 * A returned COMMIT_UNCONFIRMED outcome cannot be downgraded by later cleanup.
 */
public final class TokenSelectorPersistenceException extends RuntimeException {
    public enum Code { STORAGE_UNAVAILABLE, TRANSACTION_STATE_UNCONFIRMED }
    private final Code code;

    TokenSelectorPersistenceException(Code code) {
        super(code.name(), null, false, false);
        this.code = code;
    }

    public Code code() { return code; }

    @Override public String toString() {
        return "TokenSelectorPersistenceException[" + code.name() + "]";
    }
}
