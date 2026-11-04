package com.finsec.fuse.reimplementation.auth;

import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RegistryTokenSelectionTest {
    @Test void bindsRegistryWithoutReplacingSelectorAndKeepsUuidDomainsIndependent() {
        UUID registry = new UUID(0, 1);
        TokenRevocationInput input = new TokenRevocationInput(new UUID(0, 2), 7);
        RegistryTokenSelection value = new RegistryTokenSelection(registry, input);
        assertEquals(registry, value.registryId());
        assertSame(input, value.input());
        assertEquals(7L, value.input().expectedRevision());
        assertNotEquals(value, new RegistryTokenSelection(new UUID(0, 3), input));
        assertEquals("RegistryTokenSelection[REDACTED]", value.toString());
    }

    @Test void rejectsMissingRegistryOrInputWithoutRenderingValues() {
        for (boolean missingRegistry : new boolean[] {true, false}) {
            IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                    () -> new RegistryTokenSelection(missingRegistry ? null : new UUID(0, 1),
                            missingRegistry ? new TokenRevocationInput(new UUID(0, 2), 0) : null));
            assertEquals("INVALID_TOKEN_REVOCATION_INPUT", error.getMessage());
            assertNull(error.getCause());
        }
    }
}
