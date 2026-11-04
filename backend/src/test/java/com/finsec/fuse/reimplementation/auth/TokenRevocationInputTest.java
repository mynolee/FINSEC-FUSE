package com.finsec.fuse.reimplementation.auth;

import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TokenRevocationInputTest {
    @Test void acceptsFullNonnegativeRevisionAndUuidDomainWithoutInventingUuidPolicy() {
        UUID nil = new UUID(0, 0);
        UUID any = UUID.fromString("ffffffff-ffff-ffff-ffff-ffffffffffff");
        assertEquals(0L, new TokenRevocationInput(nil, 0).expectedRevision());
        TokenRevocationInput value = new TokenRevocationInput(any, Long.MAX_VALUE);
        assertEquals(any, value.selectionId());
        assertEquals(Long.MAX_VALUE, value.expectedRevision());
        assertEquals(value, new TokenRevocationInput(any, Long.MAX_VALUE));
    }

    @Test void rejectsNullAndNegativeWithFixedRedactedErrorsAndNoCause() {
        for (long revision : new long[] {-1, Long.MIN_VALUE}) {
            IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                    () -> new TokenRevocationInput(new UUID(0, 0), revision));
            assertEquals("INVALID_TOKEN_REVOCATION_INPUT", error.getMessage());
            assertNull(error.getCause());
        }
        assertThrows(IllegalArgumentException.class, () -> new TokenRevocationInput(null, 0));
        assertEquals("TokenRevocationInput[REDACTED]",
                new TokenRevocationInput(new UUID(0, 0), 0).toString());
    }
}
