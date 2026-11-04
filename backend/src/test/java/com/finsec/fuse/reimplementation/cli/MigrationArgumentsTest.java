package com.finsec.fuse.reimplementation.cli;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class MigrationArgumentsTest {
    private static String[] valid(String schema, String fd) {
        return new String[] {"fresh-init", "--schema", schema, "--credential-input-fd", fd, "--expect-empty"};
    }

    private static void rejected(String... args) {
        var error = assertThrows(IllegalArgumentException.class, () -> MigrationArguments.parse(args));
        assertEquals("Invalid migration arguments", error.getMessage());
        assertNull(error.getCause());
    }

    @Test void acceptsExplicitFreshInitInAnyOptionOrderAndInclusiveBounds() {
        var parsed = MigrationArguments.parse(new String[] {"fresh-init", "--expect-empty",
                "--credential-input-fd", "0", "--schema", "_synthetic"});
        assertEquals("_synthetic", parsed.schema());
        assertEquals(0, parsed.credentialInputFd());
        assertTrue(parsed.expectEmpty());
        var maximum = MigrationArguments.parse(valid("a".repeat(63), "2147483647"));
        assertEquals(63, maximum.schema().length());
        assertEquals(Integer.MAX_VALUE, maximum.credentialInputFd());
    }

    @Test void rejectsAmbiguousOrUnboundedSchemaAndDescriptorSpellings() {
        for (String schema : List.of("", "a".repeat(64), "1schema", "x.y", " x", "x ", "x;y", "é", "x\n"))
            rejected(valid(schema, "3"));
        for (String fd : List.of("", "-1", "+3", "03", " 3", "3 ", "3.0", "3e0", "2147483648", "９"))
            rejected(valid("synthetic", fd));
    }

    @Test void rejectsMissingRepeatedUnknownAndPositionalInputs() {
        rejected((String[]) null);
        rejected();
        rejected("fresh-init");
        rejected("upgrade", "--schema", "synthetic", "--credential-input-fd", "3", "--expect-empty");
        rejected("fresh-init", "--schema", "synthetic", "--credential-input-fd", "3");
        rejected("fresh-init", "--schema", "synthetic", "--expect-empty");
        rejected("fresh-init", "--credential-input-fd", "3", "--expect-empty");
        rejected("fresh-init", "--schema");
        for (String[] suffix : List.of(new String[] {"--schema", "other"},
                new String[] {"--credential-input-fd", "4"}, new String[] {"--expect-empty"},
                new String[] {"extra"}, new String[] {"--password", "synthetic-password"},
                new String[] {"--jdbc-url", "jdbc:synthetic:unused"},
                new String[] {"--user", "synthetic-user"}, new String[] {"--ttl", "1"})) {
            String[] all = Arrays.copyOf(valid("synthetic", "3"), 6 + suffix.length);
            System.arraycopy(suffix, 0, all, 6, suffix.length);
            rejected(all);
        }
        for (int i = 0; i < 6; i++) {
            String[] args = valid("synthetic", "3"); args[i] = null; rejected(args);
        }
    }

    @Test void doesNotRetainCallerArrayOrRenderInputValues() {
        String[] args = valid("synthetic_private_marker", "17");
        var parsed = MigrationArguments.parse(args);
        Arrays.fill(args, "changed");
        assertEquals("synthetic_private_marker", parsed.schema());
        assertEquals(17, parsed.credentialInputFd());
        assertFalse(parsed.toString().contains("synthetic_private_marker"));
        assertFalse(parsed.toString().contains("17"));
    }

    @Test void doesNotNormalizeConfusableOptionsOrTreatOptionTokensAsValues() {
        for (String option : List.of("\u2013\u2013schema", "--schem\u0430", "--schema\u200b", "--schema=synthetic")) {
            String[] args = valid("synthetic", "3"); args[1] = option; rejected(args);
        }
        for (String value : List.of("--expect-empty", "synthetic\0", "synthetic\u200b", "../synthetic", "a/b"))
            rejected(valid(value, "3"));
        rejected("fresh-init", "--schema", "--expect-empty", "--credential-input-fd", "3", "synthetic");
        rejected("fresh-init", "synthetic", "--schema", "--credential-input-fd", "3", "--expect-empty");
        rejected("fresh-init\u200b", "--schema", "synthetic", "--credential-input-fd", "3", "--expect-empty");
    }
}
