package com.finsec.fuse.reimplementation.auth;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Schema-derived input values only; no authentication, issuance or role/scope policy.
 * Accepted identifiers are ASCII, so Java UTF-16 ordering/length matches their
 * character count and PostgreSQL C ordering; no general Unicode codec is implied.
 */
public record TokenRegistryInput(String actorId, Role role, List<String> customerScope) {
    private static final Pattern ACTOR = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}");
    private static final Pattern CUSTOMER = Pattern.compile("customer-[A-Za-z0-9][A-Za-z0-9_-]{0,118}");

    public enum Role {
        CUSTOMER, LOAN_REVIEWER, SECURITY_OPERATOR, DEVELOPER, KYC_SERVICE, FUSE_WORKER
    }

    public TokenRegistryInput {
        if (actorId == null || !ACTOR.matcher(actorId).matches() || role == null || customerScope == null) {
            throw invalid();
        }
        if (customerScope.size() > 256) throw invalid();
        // Validate the detached copy, never a caller-owned list retained by the value.
        var copy = new ArrayList<>(customerScope);
        if (copy.size() > 256) throw invalid();
        String previous = null;
        for (String customer : copy) {
            if (customer == null || !CUSTOMER.matcher(customer).matches()
                    || (previous != null && previous.compareTo(customer) >= 0)) {
                throw invalid();
            }
            previous = customer;
        }
        // Empty scope is valid for every role in V6, including CUSTOMER.
        customerScope = List.copyOf(copy);
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("INVALID_TOKEN_REGISTRY_INPUT");
    }

    @Override public String toString() {
        return "TokenRegistryInput[REDACTED]";
    }
}
