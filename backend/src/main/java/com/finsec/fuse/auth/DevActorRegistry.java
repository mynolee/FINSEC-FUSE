package com.finsec.fuse.auth;

import com.finsec.fuse.config.SecurityPolicy;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/** Demo/test admission reads durable authority; construction never connects or issues credentials. */
@Component
public final class DevActorRegistry {
    private final DemoTokenStore store;
    private final List<DemoTokenStore.Binding> configured;
    private final boolean demo;
    public DevActorRegistry(Environment env,SecurityPolicy policy,DemoTokenStore store) {
        this.store=Objects.requireNonNull(store);
        if(policy.devTokenTtlSeconds()!=7200)throw new IllegalStateException("Unsupported authentication policy");
        var profiles=env.getActiveProfiles().length==0?env.getDefaultProfiles():env.getActiveProfiles();
        demo=profiles.length>0 && Arrays.stream(profiles).allMatch(p->p.equals("demo")||p.equals("test"));
        var bindings=new ArrayList<DemoTokenStore.Binding>();
        Set<String> customers=Set.of("customer-101","customer-102","customer-103","customer-104");
        for(int n=101;n<=104;n++)add(bindings,env,"CUSTOMER_"+n,"customer-"+n,new Actor("customer-"+n,"CUSTOMER",Set.of("customer-"+n)));
        add(bindings,env,"REVIEWER","reviewer",new Actor("staff-01","LOAN_REVIEWER",scope(env.getProperty("FUSE_REVIEWER_CUSTOMERS"),customers)));
        add(bindings,env,"SECURITY","security",new Actor("security-01","SECURITY_OPERATOR",scope(env.getProperty("FUSE_SECURITY_CUSTOMERS"),customers)));
        add(bindings,env,"DEVELOPER","developer",new Actor("developer-01","DEVELOPER",Set.of()));
        if(demo)addToken(bindings,env.getProperty("FUSE_SERVICE_TOKEN",env.getProperty("fuse.service-token","")),new Actor("kyc-service","KYC_SERVICE",Set.of()));
        configured=List.copyOf(bindings);
    }
    private void add(List<DemoTokenStore.Binding> bindings,Environment env,String suffix,String property,Actor actor) {
        addToken(bindings,env.getProperty("FUSE_DEV_"+suffix+"_TOKEN",env.getProperty("FUSE_"+suffix+"_TOKEN",env.getProperty("fuse.auth."+property+"-token",""))),actor);
    }
    private void addToken(List<DemoTokenStore.Binding> bindings,String token,Actor actor) {
        if(token==null||token.isBlank()||token.equals("CHANGE_ME"))return;
        if(!demo)throw new IllegalStateException("Development authentication requires an exclusively demo/test profile");
        if(!validToken(token))throw new IllegalStateException("Development tokens must encode at least 32 random bytes");
        var binding=new DemoTokenStore.Binding(fingerprint(token),actor);
        if(bindings.stream().anyMatch(b->sameFingerprint(b.fingerprint(),binding.fingerprint())))throw new IllegalStateException("Authentication tokens must be distinct across actors");
        bindings.add(binding);
    }
    public List<DemoTokenStore.Binding> configuredBindings() { return configured; }
    public void requireReady() {
        if(demo)store.requireReady(configured);
    }
    public Actor resolve(String token) {
        if(!demo || !validToken(token))return null;
        var snapshot=store.lookup(fingerprint(token),configured);
        var credential=snapshot.credential();var now=snapshot.authorityTime();
        if(credential==null || !sameFingerprint(fingerprint(token),credential.fingerprint()) || credential.status()!=DemoTokenStore.Status.ACTIVE || now.isBefore(credential.issuedAt()) || !now.isBefore(credential.expiresAt()))return null;
        return credential.actor();
    }
    public static String generateToken() { byte[] bytes=new byte[32];new SecureRandom().nextBytes(bytes);return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
    public static boolean validToken(String token) {
        if(token==null || token.contains("CHANGE_ME") || token.length()>256)return false;
        try {
            if(token.matches("[0-9a-fA-F]{64,}"))return token.length()%2==0;
            if(!token.matches("[A-Za-z0-9_-]{43,}"))return false;
            byte[] bytes=Base64.getUrlDecoder().decode(token);
            return bytes.length>=32 && Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(token);
        } catch(IllegalArgumentException invalid) { return false; }
    }
    public static String fingerprint(String token) {
        try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));}
        catch(NoSuchAlgorithmException impossible){throw new IllegalStateException("Credential digest is unavailable");}
    }
    static boolean sameFingerprint(String first,String second) {
        return MessageDigest.isEqual(HexFormat.of().parseHex(first),HexFormat.of().parseHex(second));
    }
    private static Set<String> scope(String source,Set<String> fallback) {
        return source==null?fallback:DemoTokenStore.canonicalScope(Arrays.stream(source.split(",")).map(String::trim).filter(s->!s.isEmpty()).collect(Collectors.toSet()));
    }
}
