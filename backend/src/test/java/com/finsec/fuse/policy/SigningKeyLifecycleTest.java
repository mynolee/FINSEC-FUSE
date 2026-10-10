package com.finsec.fuse.policy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.env.MockEnvironment;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
class SigningKeyLifecycleTest {
    @TempDir Path directory;
    @Test void rotationRetainsVerificationButRevocationRejectsImmediately() {
        byte[] old=new byte[32],current=new byte[32];current[0]=1;
        var rotated=new SigningKeyProvider("new",Map.of("new",new SigningKeyProvider.Entry(current,SigningKeyProvider.State.ISSUING),"old",new SigningKeyProvider.Entry(old,SigningKeyProvider.State.VERIFY_ONLY)),true);
        assertEquals("new",rotated.activeKid());assertArrayEquals(old,rotated.key("old"));
        var revoked=new SigningKeyProvider("new",Map.of("new",new SigningKeyProvider.Entry(current,SigningKeyProvider.State.ISSUING),"old",new SigningKeyProvider.Entry(old,SigningKeyProvider.State.REVOKED)),true);
        assertThrows(PolicyException.class,()->revoked.key("old"));
        assertThrows(PolicyException.class,()->rotated.key("../../old"));
        assertThrows(IllegalArgumentException.class,()->new SigningKeyProvider("old",Map.of("old",new SigningKeyProvider.Entry(old,SigningKeyProvider.State.VERIFY_ONLY)),true));
    }
    @Test void startupChecksPrivateFileAndRejectsPlaceholderAndSymlink() throws Exception {
        byte[] generated=new byte[32];new java.security.SecureRandom().nextBytes(generated);
        Path key=directory.resolve("key");Files.write(key,generated);Files.setPosixFilePermissions(key,PosixFilePermissions.fromString("rw-------"));
        var env=new MockEnvironment().withProperty("FUSE_SIGNING_KEY_PATH",key.toString());
        assertDoesNotThrow(()->new SigningKeyProvider(env));
        Files.write(key,new byte[32]);assertThrows(IllegalStateException.class,()->new SigningKeyProvider(env));
        byte[] repeated=new byte[32];Arrays.fill(repeated,(byte)0x41);Files.write(key,repeated);assertThrows(IllegalStateException.class,()->new SigningKeyProvider(env));
        Files.write(key,generated);
        Files.setPosixFilePermissions(key,PosixFilePermissions.fromString("rw-r--r--"));assertThrows(IllegalStateException.class,()->new SigningKeyProvider(env));
        Files.setPosixFilePermissions(key,PosixFilePermissions.fromString("rw-------"));Files.writeString(key,"CHANGE_ME".repeat(8));assertThrows(IllegalStateException.class,()->new SigningKeyProvider(env));
        Path link=directory.resolve("link");Files.createSymbolicLink(link,key);assertThrows(IllegalStateException.class,()->new SigningKeyProvider(new MockEnvironment().withProperty("FUSE_SIGNING_KEY_PATH",link.toString())));
    }
}
