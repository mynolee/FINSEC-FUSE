package com.finsec.fuse.reimplementation.cli;

import com.finsec.fuse.reimplementation.auth.TokenRevocationInput;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/** Proposed isolated input parser, with no main, descriptor read, DB or revoke action.
 * Descriptor syntax does not establish ownership, protected channels or authority.
 * Existing TokenAdminArguments and its unsupported revoke behavior are unchanged.
 */
public final class TokenRevocationArguments {
    private static final String ERROR = "INVALID_TOKEN_REVOCATION_ARGUMENTS";
    private static final Pattern SCHEMA = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,62}");
    private static final Pattern DECIMAL = Pattern.compile("0|[1-9][0-9]*");
    private static final Pattern UUID_TEXT = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final Set<String> OPTIONS = Set.of("--schema", "--credential-input-fd",
            "--selection-id", "--expected-revision");

    private TokenRevocationArguments() {}

    public record Revoke(String schema, int credentialInputFd, TokenRevocationInput input) {
        public Revoke {
            if (schema == null || !SCHEMA.matcher(schema).matches()
                    || credentialInputFd < 0 || input == null) throw invalid();
        }
        @Override public String toString() { return "TokenRevocationArguments.Revoke[REDACTED]"; }
    }

    /** Exact singleton pairs after verb, with no environment defaults or registry override. */
    public static Revoke parse(String[] arguments) {
        if (arguments == null) throw invalid();
        String[] values = arguments.clone();
        if (values.length != 9 || !"revoke".equals(values[0])) throw invalid();
        Map<String, String> options = new HashMap<>();
        for (int index = 1; index < values.length; index += 2) {
            String key = values[index];
            String value = values[index + 1];
            if (key == null || value == null || !OPTIONS.contains(key)
                    || options.putIfAbsent(key, value) != null) throw invalid();
        }
        if (!options.keySet().equals(OPTIONS)) throw invalid();
        String selector = options.get("--selection-id");
        if (!UUID_TEXT.matcher(selector).matches()) throw invalid();
        try {
            UUID selectionId = UUID.fromString(selector);
            if (!selectionId.toString().equals(selector)) throw invalid();
            int descriptor = Integer.parseInt(decimal(options.get("--credential-input-fd"), 10));
            long revision = Long.parseLong(decimal(options.get("--expected-revision"), 19));
            return new Revoke(options.get("--schema"), descriptor,
                    new TokenRevocationInput(selectionId, revision));
        } catch (IllegalArgumentException rejected) {
            throw invalid();
        }
    }

    private static String decimal(String value, int maximumLength) {
        if (value == null || value.length() > maximumLength || !DECIMAL.matcher(value).matches()) {
            throw invalid();
        }
        return value;
    }

    private static IllegalArgumentException invalid() { return new IllegalArgumentException(ERROR); }
}
