package com.finsec.fuse.policy;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/** Server-owned key registry. IDs never select filesystem paths supplied by a caller. */
@Component
public final class SigningKeyProvider {
    public enum State { ISSUING, VERIFY_ONLY, REVOKED }
    public record Entry(byte[] material, State state) {
        public Entry { material=material.clone(); Objects.requireNonNull(state); }
        @Override public byte[] material() { return material.clone(); }
    }
    private final String activeKid;
    private final Map<String, Entry> keys;

    @Autowired
    public SigningKeyProvider(Environment environment) {
        activeKid=environment.getProperty("FUSE_SIGNING_KEY_ID", "local-v1");
        String path=environment.getProperty("FUSE_SIGNING_KEY_PATH", environment.getProperty("fuse.signing-key-path", ""));
        Map<String,Entry> registry=new HashMap<>();
        byte[] key;
        if(path.isBlank() && Arrays.asList(environment.getActiveProfiles()).contains("test")) {
            key=new byte[32];new SecureRandom().nextBytes(key);
        } else key=readKey(path);
        registry.put(activeKid,new Entry(key,State.ISSUING));
        // Explicit server configuration: kid:STATE:path entries; no client-controlled paths.
        String previous=environment.getProperty("FUSE_VERIFY_KEYS", "");
        if(!previous.isBlank()) for(String value:previous.split(",")) {
            String[] parts=value.split(":",3);
            if(parts.length!=3 || parts[0].equals(activeKid) || registry.containsKey(parts[0]))
                throw new IllegalStateException("Invalid signing key registry");
            State state=State.valueOf(parts[1]);
            if(state==State.ISSUING)throw new IllegalStateException("Only one issuing key is permitted");
            registry.put(parts[0],new Entry(readKey(parts[2]),state));
        }
        keys=validated(activeKid,registry);
    }
    public SigningKeyProvider(String activeKid, Map<String,byte[]> keys) {
        this.activeKid=activeKid;
        Map<String,Entry> entries=new HashMap<>();
        keys.forEach((id,key)->entries.put(id,new Entry(key,id.equals(activeKid)?State.ISSUING:State.VERIFY_ONLY)));
        this.keys=validated(activeKid,entries);
    }
    public SigningKeyProvider(String activeKid, Map<String,Entry> keys, boolean explicitLifecycle) {
        this.activeKid=activeKid;this.keys=validated(activeKid,keys);
    }
    private static Map<String,Entry> validated(String activeKid,Map<String,Entry> entries) {
        Map<String,Entry> copy=new HashMap<>();
        entries.forEach((id,entry)-> {
            if(id==null || !id.matches("[A-Za-z0-9._-]{1,64}") || entry.material().length<32)
                throw new IllegalArgumentException("A fixed key ID and at least 32 key bytes are required");
            copy.put(id,new Entry(entry.material(),entry.state()));
        });
        if(!copy.containsKey(activeKid) || copy.get(activeKid).state()!=State.ISSUING
                || copy.values().stream().filter(e->e.state()==State.ISSUING).count()!=1)
            throw new IllegalArgumentException("Exactly one current issuing key is required");
        return Map.copyOf(copy);
    }
    private static byte[] readKey(String path) {
        if(path.isBlank())throw new IllegalStateException("Signing key configuration is required");
        try {
            Path file=Path.of(path);
            if(!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(file)
                    || !Files.getPosixFilePermissions(file,LinkOption.NOFOLLOW_LINKS).equals(Set.of(PosixFilePermission.OWNER_READ,PosixFilePermission.OWNER_WRITE))
                    || Files.size(file)<32 || Files.size(file)>4096)
                throw new IllegalStateException("Signing key file must be private, regular and bounded");
            byte[] key;
            try(var input=Files.newInputStream(file,LinkOption.NOFOLLOW_LINKS)) { key=input.readNBytes(4097); }
            if(key.length<32 || key.length>4096)throw new IllegalStateException("Invalid signing key size");
            boolean repeated=true;
            for(int i=1;i<key.length;i++)repeated &= key[i]==key[0];
            if(repeated || new String(key,java.nio.charset.StandardCharsets.UTF_8).contains("CHANGE_ME"))
                throw new IllegalStateException("Placeholder signing key is forbidden");
            return key;
        } catch(IOException | UnsupportedOperationException e) {
            throw new IllegalStateException("Cannot validate private signing key file");
        }
    }
    public String activeKid() { return activeKid; }
    byte[] key(String kid) {
        Entry entry=keys.get(kid);
        if(entry==null || entry.state()==State.REVOKED)throw new PolicyException("SIGNATURE_INVALID");
        return entry.material();
    }
}
