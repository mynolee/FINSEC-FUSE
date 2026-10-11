package com.finsec.fuse.auth;

import java.lang.reflect.InvocationTargetException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

/** File-safety tests use synthetic outputs only and never connect to or issue a database credential. */
class DemoTokenProvisionerTest {
    @TempDir Path directory;
    @Test void privateOutputIsNewPrivateAndNeverOverwritesOrFollowsSymlinks()throws Exception {
        assumeFalse("root".equals(System.getProperty("user.name")));
        Files.setPosixFilePermissions(directory,PosixFilePermissions.fromString("rwx------"));
        Path output=directory.resolve("fresh.properties");
        try(AutoCloseable privateOutput=create(output)) {
            var write=privateOutput.getClass().getDeclaredMethod("write",String.class);write.setAccessible(true);write.invoke(privateOutput,"synthetic output only\n");
            assertEquals(PosixFilePermissions.fromString("rw-------"),Files.getPosixFilePermissions(output));
        }
        assertEquals("synthetic output only\n",Files.readString(output));
        assertThrows(InvocationTargetException.class,()->create(output));assertEquals("synthetic output only\n",Files.readString(output));
        Path link=directory.resolve("link.properties");Files.createSymbolicLink(link,output.getFileName());
        assertThrows(InvocationTargetException.class,()->create(link));assertEquals("synthetic output only\n",Files.readString(output));
        Path actual=Files.createDirectory(directory.resolve("actual"),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        Path alias=directory.resolve("alias");Files.createSymbolicLink(alias,actual.getFileName());
        assertThrows(InvocationTargetException.class,()->create(alias.resolve("new.properties")));assertFalse(Files.exists(actual.resolve("new.properties")));
    }
    @Test void outputMustHavePrivateParentAndNormalizedAbsolutePath()throws Exception {
        Files.setPosixFilePermissions(directory,PosixFilePermissions.fromString("rwxr-xr-x"));
        assertThrows(InvocationTargetException.class,()->create(directory.resolve("new.properties")));
        assertThrows(InvocationTargetException.class,()->create(Path.of("relative.properties")));
        assertThrows(InvocationTargetException.class,()->create(directory.resolve("child/../new.properties")));
    }
    @Test void noLegacyImportOrTokenArgumentIsAccepted() {
        UUID operation=UUID.fromString("00000000-0000-4000-8000-000000000001");
        for(String[] args:new String[][]{{"import"},{"init-fresh","--output","unused"},
            {"issue-fresh","--token","synthetic-forbidden-import"},{"revoke","--actor","a","--fingerprint","0".repeat(64)}})
            assertThrows(IllegalArgumentException.class,()->DemoTokenProvisioner.execute(args,Map.of(),operation));
    }
    @Test void failedConnectionPreparationPreservesPreparedOutputWithoutClaimingCommitOrOverwriting()throws Exception {
        assumeFalse("root".equals(System.getProperty("user.name")));
        Files.setPosixFilePermissions(directory,PosixFilePermissions.fromString("rwx------"));Path output=directory.resolve("prepared.properties");
        String[] args={"issue-fresh","--actor","synthetic-actor","--role","CUSTOMER","--scope","customer-101","--output",output.toString()};
        UUID operation=UUID.fromString("00000000-0000-4000-8000-000000000002");
        // Missing owner configuration fails before DriverManager or any database operation.
        assertThrows(IllegalArgumentException.class,()->DemoTokenProvisioner.execute(args,Map.of(),operation));
        String prepared=Files.readString(output);assertTrue(prepared.contains("# operation_id="+operation));assertTrue(prepared.contains("# status=PREPARED"));assertFalse(prepared.contains("# status=COMMITTED"));
        assertTrue(prepared.contains(" fingerprint="));assertTrue(prepared.contains("FUSE_FRESH_TOKEN="));
        assertThrows(Exception.class,()->DemoTokenProvisioner.execute(args,Map.of(),operation));
        assertTrue(prepared.equals(Files.readString(output)),"An unconfirmed output must be retained unchanged");
    }
    private AutoCloseable create(Path path)throws Exception {
        Class<?> output=Class.forName(DemoTokenProvisioner.class.getName()+"$PrivateOutput");
        var create=output.getDeclaredMethod("create",Path.class);create.setAccessible(true);return (AutoCloseable)create.invoke(null,path);
    }
}
