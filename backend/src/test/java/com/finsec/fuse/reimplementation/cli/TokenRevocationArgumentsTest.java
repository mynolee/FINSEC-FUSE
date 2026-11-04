package com.finsec.fuse.reimplementation.cli;

import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TokenRevocationArgumentsTest {
    private static final String ID = "00000000-0000-0000-0000-000000000000";

    private static String[] arguments() {
        return new String[] {"revoke", "--schema", "Synthetic_1", "--credential-input-fd", "0",
                "--selection-id", ID, "--expected-revision", "0"};
    }

    private static void rejects(String[] input) {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> TokenRevocationArguments.parse(input));
        assertEquals("INVALID_TOKEN_REVOCATION_ARGUMENTS", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void parsesReorderedBoundaryValuesAndDetachesSourceArray() {
        String[] args = {"revoke", "--expected-revision", "9223372036854775807",
                "--selection-id", ID, "--credential-input-fd", "2147483647",
                "--schema", "A".repeat(63)};
        var result = TokenRevocationArguments.parse(args);
        args[2] = "synthetic-mutated";
        assertEquals(Long.MAX_VALUE, result.input().expectedRevision());
        assertEquals(UUID.fromString(ID), result.input().selectionId());
        assertEquals(Integer.MAX_VALUE, result.credentialInputFd());
        assertEquals("A".repeat(63), result.schema());
        assertEquals("TokenRevocationArguments.Revoke[REDACTED]", result.toString());
    }

    @Test void rejectsNoncanonicalSelectorRevisionAndDescriptorText() {
        for (String bad : new String[] {"1-1-1-1-1", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
                ID + " ", "synthetic-bearer"}) {
            String[] args = arguments(); args[6] = bad; rejects(args);
        }
        for (String bad : new String[] {"-1", "+1", "01", "1.0", " 1", "true", "9223372036854775808"}) {
            String[] args = arguments(); args[8] = bad; rejects(args);
        }
        for (String bad : new String[] {"-1", "01", "2147483648", "1.0", " 0"}) {
            String[] args = arguments(); args[4] = bad; rejects(args);
        }
    }

    @Test void rejectsUnknownDuplicateMissingNullExtrasAndSecretOrRegistryChannels() {
        rejects(null); rejects(new String[0]);
        for (int index = 0; index < 9; index++) {
            String[] args = arguments(); args[index] = null; rejects(args);
        }
        for (String option : new String[] {"--fingerprint", "--bearer", "--password", "--jdbc-url",
                "--registry-id", "--row-index", "--actor", "--ttl", "--schema"}) {
            String[] args = arguments(); args[5] = option; rejects(args);
        }
        rejects(new String[] {"revoke", "--schema", "Synthetic_1"});
        String[] extra = java.util.Arrays.copyOf(arguments(), 10); extra[9] = "synthetic-extra";
        rejects(extra);
        String[] wrongVerb = arguments(); wrongVerb[0] = "issue"; rejects(wrongVerb);
        String[] wrongSchema = arguments(); wrongSchema[2] = "a.b"; rejects(wrongSchema);
        wrongSchema = arguments(); wrongSchema[2] = "A".repeat(64); rejects(wrongSchema);
    }

    @Test void preservesExistingParserRejectionAndDirectConstructorValidation() {
        assertThrows(IllegalArgumentException.class, () -> TokenAdminArguments.parse(arguments()));
        assertThrows(IllegalArgumentException.class,
                () -> new TokenRevocationArguments.Revoke("safe", 0, null));
        assertThrows(IllegalArgumentException.class,
                () -> new TokenRevocationArguments.Revoke("safe", -1,
                        new com.finsec.fuse.reimplementation.auth.TokenRevocationInput(new UUID(0, 0), 0)));
        assertThrows(IllegalArgumentException.class,
                () -> new TokenRevocationArguments.Revoke("bad.schema", 0,
                        new com.finsec.fuse.reimplementation.auth.TokenRevocationInput(new UUID(0, 0), 0)));
        assertEquals(0, TokenRevocationArguments.parse(arguments()).credentialInputFd());
    }
}
