package com.finsec.fuse.reimplementation.cli;

import com.finsec.fuse.reimplementation.auth.TokenRegistryInput;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import static org.junit.jupiter.api.Assertions.*;

class TokenAdminArgumentsTest {
    private static final String REGISTRY = "123e4567-e89b-42d3-a456-426614174000";

    private static String[] command(String verb, String... options) {
        var args = new ArrayList<>(List.of(verb, "--schema", "synthetic", "--credential-input-fd", "3"));
        args.addAll(Arrays.asList(options));
        return args.toArray(String[]::new);
    }

    private static String[] issue(String actor, String role, String... scopes) {
        var args = new ArrayList<>(Arrays.asList(command("issue", "--actor", actor, "--role", role,
                "--credential-output-fd", "4")));
        for (String scope : scopes) { args.add("--scope"); args.add(scope); }
        return args.toArray(String[]::new);
    }

    private static void rejected(String... args) {
        rejectedValue(() -> TokenAdminArguments.parse(args));
    }

    private static void rejectedValue(Executable action) {
        var error = assertThrows(IllegalArgumentException.class, action);
        assertEquals("INVALID_TOKEN_ADMIN_ARGUMENTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void parsesOnlyExplicitInitIssueAndListWithAnyOptionOrder() {
        var init = assertInstanceOf(TokenAdminArguments.Init.class, TokenAdminArguments.parse(
                new String[] {"init", "--registry-id", REGISTRY, "--credential-input-fd", "0",
                        "--schema", "_synthetic"}));
        assertEquals(UUID.fromString(REGISTRY), init.registryId());
        assertEquals("_synthetic", init.schema());
        assertEquals(0, init.credentialInputFd());
        var list = assertInstanceOf(TokenAdminArguments.ListTokens.class,
                TokenAdminArguments.parse(command("list", "--actor", "synthetic.actor:1")));
        assertEquals("synthetic.actor:1", list.actorId());
        for (String role : List.of("CUSTOMER", "LOAN_REVIEWER", "SECURITY_OPERATOR", "DEVELOPER", "KYC_SERVICE", "FUSE_WORKER")) {
            var parsed = assertInstanceOf(TokenAdminArguments.Issue.class,
                    TokenAdminArguments.parse(issue("synthetic", role)));
            assertEquals(role, parsed.input().role().name());
            assertTrue(parsed.input().customerScope().isEmpty());
            assertEquals(4, parsed.credentialOutputFd());
        }
    }

    @Test void enforcesCanonicalUuidAndDescriptorBounds() {
        for (String uuid : List.of(REGISTRY.toUpperCase(), "1-1-1-1-1", REGISTRY + " ", "{" + REGISTRY + "}", "synthetic"))
            rejected(command("init", "--registry-id", uuid));
        for (String fd : List.of("-1", "+3", "03", " 3", "3 ", "2147483648", "３")) {
            rejected("list", "--schema", "synthetic", "--credential-input-fd", fd, "--actor", "synthetic");
            rejected(command("issue", "--actor", "synthetic", "--role", "CUSTOMER", "--credential-output-fd", fd));
        }
        for (String fd : List.of("0", "1", "2"))
            rejected(command("issue", "--actor", "synthetic", "--role", "CUSTOMER", "--credential-output-fd", fd));
        var maximum = assertInstanceOf(TokenAdminArguments.Issue.class, TokenAdminArguments.parse(new String[] {
                "issue", "--schema", "a".repeat(63), "--credential-input-fd", "2147483647", "--actor", "a",
                "--role", "CUSTOMER", "--credential-output-fd", "2147483647"}));
        assertEquals(Integer.MAX_VALUE, maximum.credentialInputFd());
        assertEquals(Integer.MAX_VALUE, maximum.credentialOutputFd());
        for (String schema : List.of("", "a".repeat(64), "1x", "x.y", "x;y", "é", " x"))
            rejected("list", "--schema", schema, "--credential-input-fd", "3", "--actor", "synthetic");
    }

    @Test void enforcesV6ActorAndSortedUniqueBoundedScopeWithoutInventingRolePolicy() {
        assertNotNull(TokenAdminArguments.parse(issue("a".repeat(128), "CUSTOMER", "customer-" + "a".repeat(119))));
        for (String actor : List.of("", "a".repeat(129), "_actor", "actor/1", "é", "actor\n")) {
            rejected(issue(actor, "CUSTOMER"));
            rejected(command("list", "--actor", actor));
        }
        for (String role : List.of("customer", "ADMIN", "CUSTOMER ", "")) rejected(issue("synthetic", role));
        for (String scope : List.of("", "customer-", "customer-_a", "customer-" + "a".repeat(120), "customer-a.b", "customer-é"))
            rejected(issue("synthetic", "CUSTOMER", scope));
        rejected(issue("synthetic", "CUSTOMER", "customer-b", "customer-a"));
        rejected(issue("synthetic", "CUSTOMER", "customer-a", "customer-a"));
        String[] scopes = new String[256];
        for (int i = 0; i < scopes.length; i++) scopes[i] = "customer-" + String.format(java.util.Locale.ROOT, "%03d", i);
        var parsed = assertInstanceOf(TokenAdminArguments.Issue.class, TokenAdminArguments.parse(issue("synthetic", "CUSTOMER", scopes)));
        assertEquals(256, parsed.input().customerScope().size());
        assertThrows(UnsupportedOperationException.class, () -> parsed.input().customerScope().add("customer-z"));
        String[] tooMany = Arrays.copyOf(scopes, 257); tooMany[256] = "customer-z";
        rejected(issue("synthetic", "CUSTOMER", tooMany));
    }

    @Test void rejectsNullMissingRepeatedForeignAndUnimplementedInputs() {
        rejected((String[]) null); rejected(); rejected("init"); rejected("issue"); rejected("list");
        rejected("list", "--credential-input-fd", "3", "--actor", "synthetic");
        rejected("list", "--schema", "synthetic", "--actor", "synthetic");
        rejected(command("init")); rejected(command("list"));
        rejected(command("issue", "--actor", "synthetic", "--role", "CUSTOMER"));
        rejected(command("issue", "--actor", "synthetic", "--credential-output-fd", "4"));
        rejected(command("issue", "--role", "CUSTOMER", "--credential-output-fd", "4"));
        rejected(command("revoke", "--fingerprint", "synthetic", "--expected-revision", "0"));
        rejected(command("list", "--actor"));
        for (String[] extra : List.of(new String[] {"--schema", "other"}, new String[] {"--credential-input-fd", "4"},
                new String[] {"--actor", "other"}, new String[] {"extra"}, new String[] {"--jdbc-url", "jdbc:synthetic:unused"},
                new String[] {"--password", "synthetic-password"}, new String[] {"--user", "synthetic-user"},
                new String[] {"--bearer", "synthetic-bearer"}, new String[] {"--ttl", "7200"},
                new String[] {"--registry-id", REGISTRY}, new String[] {"--scope", "customer-a"})) {
            var args = new ArrayList<>(Arrays.asList(command("list", "--actor", "synthetic")));
            args.addAll(Arrays.asList(extra)); rejected(args.toArray(String[]::new));
        }
        for (String[] extra : List.of(new String[] {"--role", "CUSTOMER"}, new String[] {"--credential-output-fd", "4"})) {
            var args = new ArrayList<>(Arrays.asList(issue("synthetic", "CUSTOMER")));
            args.addAll(Arrays.asList(extra)); rejected(args.toArray(String[]::new));
        }
        rejected(command("init", "--registry-id", REGISTRY, "--registry-id", REGISTRY));
        String[] valid = issue("synthetic", "CUSTOMER", "customer-a");
        for (int i = 0; i < valid.length; i++) { String[] copy = valid.clone(); copy[i] = null; rejected(copy); }
    }

    @Test void detachedResultsAndErrorRenderingDoNotExposeSyntheticValues() {
        String[] args = issue("synthetic_actor_marker", "CUSTOMER", "customer-private-marker");
        var parsed = assertInstanceOf(TokenAdminArguments.Issue.class, TokenAdminArguments.parse(args));
        Arrays.fill(args, "changed");
        assertEquals("synthetic_actor_marker", parsed.input().actorId());
        assertEquals(List.of("customer-private-marker"), parsed.input().customerScope());
        for (Object value : List.of(parsed, TokenAdminArguments.parse(command("init", "--registry-id", REGISTRY)),
                TokenAdminArguments.parse(command("list", "--actor", "synthetic_actor_marker")))) {
            assertTrue(value.toString().contains("REDACTED"));
            for (String marker : List.of("synthetic", REGISTRY, "customer-private-marker")) assertFalse(value.toString().contains(marker));
        }
    }

    @Test void publicValueConstructorsCannotBypassTheParserValidationContract() {
        var input = new TokenRegistryInput("synthetic", TokenRegistryInput.Role.CUSTOMER, List.of());
        for (String schema : Arrays.asList(null, "", "../synthetic", "synthetic\u200b", "a".repeat(64))) {
            rejectedValue(() -> new TokenAdminArguments.Init(schema, 3, UUID.fromString(REGISTRY)));
            rejectedValue(() -> new TokenAdminArguments.Issue(schema, 3, input, 4));
            rejectedValue(() -> new TokenAdminArguments.ListTokens(schema, 3, "synthetic"));
        }
        rejectedValue(() -> new TokenAdminArguments.Init("synthetic", -1, UUID.fromString(REGISTRY)));
        rejectedValue(() -> new TokenAdminArguments.Init("synthetic", 3, null));
        rejectedValue(() -> new TokenAdminArguments.Issue("synthetic", -1, input, 4));
        rejectedValue(() -> new TokenAdminArguments.Issue("synthetic", 3, null, 4));
        for (int output : new int[] {-1, 0, 1, 2})
            rejectedValue(() -> new TokenAdminArguments.Issue("synthetic", 3, input, output));
        rejectedValue(() -> new TokenAdminArguments.ListTokens("synthetic", -1, "synthetic"));
        for (String actor : Arrays.asList(null, "", "synthetic\0", "synthetic\u200b", "../synthetic"))
            rejectedValue(() -> new TokenAdminArguments.ListTokens("synthetic", 3, actor));
        assertEquals(0, new TokenAdminArguments.Init("synthetic", 0, UUID.fromString(REGISTRY)).credentialInputFd());
        assertTrue(new TokenAdminArguments.Issue("synthetic", 3, input, 3).input().customerScope().isEmpty());
    }

    @Test void rejectsConfusableFlagsAndOptionTokensInValuePositionsWithoutNormalization() {
        for (String option : List.of("\u2013\u2013actor", "--act\u043er", "--actor\u200b", "--actor=synthetic"))
            rejected(command("list", option, "synthetic"));
        for (String actor : List.of("synthetic\0", "synthetic\u200b", "--schema", "../synthetic"))
            rejected(command("list", "--actor", actor));
        rejected(command("list\u200b", "--actor", "synthetic"));
        rejected(command("list", "synthetic", "--actor"));
        rejected(command("issue", "--actor", "synthetic", "--role", "CUST\u039fMER", "--credential-output-fd", "4"));
        rejected(issue("synthetic", "CUSTOMER", "customer-\u0430"));
    }
}
