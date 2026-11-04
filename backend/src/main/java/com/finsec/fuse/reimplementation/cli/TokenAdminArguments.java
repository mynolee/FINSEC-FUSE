package com.finsec.fuse.reimplementation.cli;

import com.finsec.fuse.reimplementation.auth.TokenRegistryInput;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * New v1 token-administration argument grammar only; not an executable CLI.
 * Does not open descriptors, read credentials, access a DB, issue tokens or grant
 * authority. Descriptor numbers do not prove protected channels or ownership.
 */
public final class TokenAdminArguments {
    private static final Pattern SCHEMA = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,62}");
    private static final Pattern FD = Pattern.compile("0|[1-9][0-9]*");
    private static final String ERROR = "INVALID_TOKEN_ADMIN_ARGUMENTS";

    private TokenAdminArguments() {}

    public sealed interface Command permits Init, Issue, ListTokens {
        String schema();
        int credentialInputFd();
    }

    public record Init(String schema, int credentialInputFd, UUID registryId) implements Command {
        public Init {
            globals(schema, credentialInputFd);
            if (registryId == null) throw invalid();
        }
        @Override public String toString() { return "TokenAdminArguments.Init[REDACTED]"; }
    }

    public record Issue(String schema, int credentialInputFd, TokenRegistryInput input,
                        int credentialOutputFd) implements Command {
        public Issue {
            globals(schema, credentialInputFd);
            if (input == null || credentialOutputFd < 3) throw invalid();
        }
        @Override public String toString() { return "TokenAdminArguments.Issue[REDACTED]"; }
    }

    public record ListTokens(String schema, int credentialInputFd, String actorId) implements Command {
        public ListTokens {
            globals(schema, credentialInputFd);
            registryInput(actorId, TokenRegistryInput.Role.CUSTOMER, List.of());
        }
        @Override public String toString() { return "TokenAdminArguments.ListTokens[REDACTED]"; }
    }

    /** Verb first; exact named options follow in any order, without environment defaults. */
    public static Command parse(String[] arguments) {
        if (arguments == null || arguments.length == 0) throw invalid();
        String[] args = arguments.clone();
        for (String arg : args) if (arg == null) throw invalid();
        Set<String> accepted = switch (args[0]) {
            case "init" -> Set.of("--schema", "--credential-input-fd", "--registry-id");
            case "issue" -> Set.of("--schema", "--credential-input-fd", "--actor", "--role",
                    "--scope", "--credential-output-fd");
            case "list" -> Set.of("--schema", "--credential-input-fd", "--actor");
            default -> throw invalid();
        };
        var options = new HashMap<String, String>();
        var scopes = new ArrayList<String>();
        for (int index = 1; index < args.length; index += 2) {
            String option = args[index];
            if (!accepted.contains(option) || index + 1 >= args.length
                    || args[index + 1].startsWith("--")) throw invalid();
            String value = args[index + 1];
            if (option.equals("--scope")) {
                if (scopes.size() == 256) throw invalid();
                scopes.add(value);
            } else if (options.putIfAbsent(option, value) != null) {
                throw invalid();
            }
        }
        String schema = options.get("--schema");
        int inputFd = descriptor(options.get("--credential-input-fd"));
        globals(schema, inputFd);
        return switch (args[0]) {
            case "init" -> new Init(schema, inputFd, registryId(options.get("--registry-id")));
            case "issue" -> new Issue(schema, inputFd,
                    registryInput(options.get("--actor"), role(options.get("--role")), scopes),
                    descriptor(options.get("--credential-output-fd")));
            case "list" -> new ListTokens(schema, inputFd, options.get("--actor"));
            default -> throw invalid();
        };
    }

    private static void globals(String schema, int inputFd) {
        if (schema == null || !SCHEMA.matcher(schema).matches() || inputFd < 0) throw invalid();
    }

    private static int descriptor(String value) {
        if (value == null || value.length() > 10 || !FD.matcher(value).matches()) throw invalid();
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException rejected) {
            throw invalid();
        }
    }

    private static UUID registryId(String value) {
        if (value == null) throw invalid();
        try {
            UUID id = UUID.fromString(value);
            if (!id.toString().equals(value)) throw invalid();
            return id;
        } catch (IllegalArgumentException rejected) {
            throw invalid();
        }
    }

    private static TokenRegistryInput.Role role(String value) {
        if (value == null) throw invalid();
        try {
            return TokenRegistryInput.Role.valueOf(value);
        } catch (IllegalArgumentException rejected) {
            throw invalid();
        }
    }

    private static TokenRegistryInput registryInput(String actor, TokenRegistryInput.Role role, List<String> scopes) {
        try {
            return new TokenRegistryInput(actor, role, scopes);
        } catch (IllegalArgumentException rejected) {
            throw invalid();
        }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException(ERROR);
    }
}
