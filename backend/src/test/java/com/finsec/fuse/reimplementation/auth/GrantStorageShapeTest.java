package com.finsec.fuse.reimplementation.auth;

import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class GrantStorageShapeTest {
    private static final UUID ID = UUID.fromString("00000000-0000-4000-8000-000000000501");
    private static final GrantStorageShape.AllowedAction ACTION = GrantStorageShape.AllowedAction.EVALUATE_KYC;

    @Test void acceptsEveryActionAtEveryValidDepthWithoutInventingRoleOrActionMapping() {
        assertEquals(3, GrantStorageShape.AllowedAction.values().length);
        for (var action : GrantStorageShape.AllowedAction.values()) {
            validate(1, null, null, null, null, ID, ID, action, new byte[32]);
            validate(2, ID, ID, ID, null, ID, ID, action, new byte[32]);
            validate(3, ID, ID, ID, ID, ID, ID, action, new byte[32]);
        }
        // Repeated UUIDs are intentionally accepted: this is not relational validation.
    }

    @Test void exhaustivelyChecksAllNullableCombinationsAgainstTheSqlDepthMatrix() {
        for (int depth = 1; depth <= 3; depth++) {
            for (int mask = 0; mask < 16; mask++) {
                UUID sourceRun = (mask & 1) != 0 ? ID : null;
                UUID sourceResult = (mask & 2) != 0 ? ID : null;
                UUID parent = (mask & 4) != 0 ? ID : null;
                UUID approval = (mask & 8) != 0 ? ID : null;
                int selectedDepth = depth;
                Runnable candidate = () -> validate(selectedDepth, sourceRun, sourceResult, parent,
                        approval, ID, ID, ACTION, new byte[32]);
                boolean valid = (depth == 1 && mask == 0) || (depth == 2 && mask == 7)
                        || (depth == 3 && mask == 15);
                if (valid) assertDoesNotThrow(candidate::run);
                else assertInvalid(candidate);
            }
        }
    }

    @Test void rejectsOutOfRangeDepthAndMissingRequiredValuesWithFixedDiagnostics() {
        for (int depth : new int[]{Integer.MIN_VALUE, 0, 4, Integer.MAX_VALUE}) {
            assertInvalid(() -> validate(depth, null, null, null, null, ID, ID, ACTION, new byte[32]));
        }
        assertInvalid(() -> validate(1, null, null, null, null, null, ID, ACTION, new byte[32]));
        assertInvalid(() -> validate(1, null, null, null, null, ID, null, ACTION, new byte[32]));
        assertInvalid(() -> validate(1, null, null, null, null, ID, ID, null, new byte[32]));
    }

    @Test void checksOnlyMacByteLengthWithoutRetainingOrInterpretingContents() {
        for (byte[] mac : new byte[][]{null, new byte[0], new byte[31], new byte[33]}) {
            assertInvalid(() -> validate(1, null, null, null, null, ID, ID, ACTION, mac));
        }
        byte[] mac = new byte[32];
        validate(1, null, null, null, null, ID, ID, ACTION, mac);
        Arrays.fill(mac, (byte) 0xFF);
        validate(1, null, null, null, null, ID, ID, ACTION, mac);
    }

    private static void validate(int depth, UUID run, UUID result, UUID parent, UUID approval,
                                 UUID target, UUID actionId, GrantStorageShape.AllowedAction action,
                                 byte[] mac) {
        GrantStorageShape.validate(depth, run, result, parent, approval, target, actionId, action, mac);
    }

    private static void assertInvalid(Runnable work) {
        var error = assertThrows(IllegalArgumentException.class, work::run);
        assertEquals("INVALID_GRANT_STORAGE_SHAPE", error.getMessage());
        assertNull(error.getCause());
    }
}
