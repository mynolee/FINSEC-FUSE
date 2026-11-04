package com.finsec.fuse.reimplementation.auth;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TokenRegistryInputTest {
    private static final TokenRegistryInput.Role ROLE = TokenRegistryInput.Role.CUSTOMER;

    @Test void acceptsEverySchemaRoleAndEmptyScopeWithoutInventingRolePolicy() {
        assertEquals(6, TokenRegistryInput.Role.values().length);
        for (var role : TokenRegistryInput.Role.values()) {
            assertTrue(new TokenRegistryInput("synthetic-actor", role, List.of()).customerScope().isEmpty());
            assertEquals(List.of("customer-A"),
                    new TokenRegistryInput("synthetic-actor", role, List.of("customer-A")).customerScope());
        }
    }

    @Test void usesExactAsciiActorGrammarAndLength() {
        new TokenRegistryInput("A" + "a".repeat(127), ROLE, List.of());
        new TokenRegistryInput("A_.:-09", ROLE, List.of());
        for (String actor : Arrays.asList(null, "", " ", "_a", "a/b", "한글", "a\n", "A".repeat(129))) {
            assertInvalid(() -> new TokenRegistryInput(actor, ROLE, List.of()));
        }
        assertInvalid(() -> new TokenRegistryInput("synthetic", null, List.of()));
    }

    @Test void requiresCanonicalOrderedUniqueNonNullSchemaScopes() {
        var scope = List.of("customer-A", "customer-Z", "customer-a", "customer-z");
        assertEquals(scope, new TokenRegistryInput("synthetic", ROLE, scope).customerScope());
        new TokenRegistryInput("synthetic", ROLE, List.of("customer-A" + "a".repeat(118)));
        for (List<String> invalid : List.of(
                List.of("customer-"), List.of("customer-_a"), List.of("customer-a.b"),
                List.of("customer-한글"), List.of("customer-A" + "a".repeat(119)),
                List.of("customer-b", "customer-a"), List.of("customer-a", "customer-a"),
                Arrays.asList("customer-a", null))) {
            assertInvalid(() -> new TokenRegistryInput("synthetic", ROLE, invalid));
        }
        assertInvalid(() -> new TokenRegistryInput("synthetic", ROLE, null));
    }

    @Test void accepts256ScopesButRejects257AndDoesNotNormalizeInputs() {
        var scope = IntStream.range(0, 256).mapToObj(n -> "customer-" + String.format(Locale.ROOT, "%03d", n)).toList();
        assertEquals(256, new TokenRegistryInput("synthetic", ROLE, scope).customerScope().size());
        var oversized = new ArrayList<>(scope);
        oversized.add("customer-256");
        assertInvalid(() -> new TokenRegistryInput("synthetic", ROLE, oversized));
        assertInvalid(() -> new TokenRegistryInput(" synthetic", ROLE, List.of()));
        assertInvalid(() -> new TokenRegistryInput("synthetic", ROLE, List.of(" customer-a")));
    }

    @Test void detachesTheListAndRedactsAutomaticDiagnostics() {
        var original = new ArrayList<>(List.of("customer-a"));
        var input = new TokenRegistryInput("synthetic-actor", ROLE, original);
        original.set(0, "customer-b");
        assertEquals(List.of("customer-a"), input.customerScope());
        assertThrows(UnsupportedOperationException.class, () -> input.customerScope().clear());
        assertEquals("TokenRegistryInput[REDACTED]", input.toString());
    }

    @Test void nonAsciiCodePointsNulAndSurrogatesCannotEnterTheAsciiSqlDomain() {
        String supplementary = new String(Character.toChars(0x1F600));
        for (String suffix : List.of(supplementary, String.valueOf((char) 0), String.valueOf((char) 0xD800))) {
            assertInvalid(() -> new TokenRegistryInput("A" + suffix, ROLE, List.of()));
            assertInvalid(() -> new TokenRegistryInput("synthetic", ROLE, List.of("customer-A" + suffix)));
        }
        // Both endpoints are ASCII; Java length is the same count used by V6's regex.
        String actor = "A".repeat(128);
        String customer = "customer-" + "A".repeat(119);
        assertEquals(128, new TokenRegistryInput(actor, ROLE, List.of(customer)).actorId().length());
        assertEquals(customer, new TokenRegistryInput(actor, ROLE, List.of(customer)).customerScope().getFirst());
    }

    private static void assertInvalid(Runnable work) {
        var failure = assertThrows(IllegalArgumentException.class, work::run);
        assertEquals("INVALID_TOKEN_REGISTRY_INPUT", failure.getMessage());
    }
}
