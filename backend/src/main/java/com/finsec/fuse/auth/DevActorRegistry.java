package com.finsec.fuse.auth;

import com.finsec.fuse.config.SecurityPolicy;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/** Local demo-only registry. No public mutation API and no raw tokens retained. */
@Component
public final class DevActorRegistry {
    public enum Status { ACTIVE, REVOKED }
    public record Registration(Actor actor, Instant createdAt, Instant expiresAt, Status status) {}
    private record Entry(byte[] digest, Registration registration) {}
    private final List<Entry> entries=new ArrayList<>();
    private final Clock clock;
    private final int ttl;
    @Autowired public DevActorRegistry(Environment env, SecurityPolicy policy) { this(env,policy,Clock.systemUTC()); }
    public DevActorRegistry(Environment env, SecurityPolicy policy, Clock clock) {
        this.clock=clock; this.ttl=policy.devTokenTtlSeconds();
        var profiles=env.getActiveProfiles().length==0?env.getDefaultProfiles():env.getActiveProfiles();
        boolean demo=Arrays.stream(profiles).allMatch(p->p.equals("demo")||p.equals("test")) && profiles.length>0;
        Set<String> customers=Set.of("customer-101","customer-102","customer-103","customer-104");
        for(int n=101;n<=104;n++) add(env,"CUSTOMER_"+n,"customer-"+n,new Actor("customer-"+n,"CUSTOMER",Set.of("customer-"+n)),demo);
        add(env,"REVIEWER","reviewer",new Actor("staff-01","LOAN_REVIEWER",scope(env.getProperty("FUSE_REVIEWER_CUSTOMERS"),customers)),demo);
        add(env,"SECURITY","security",new Actor("security-01","SECURITY_OPERATOR",scope(env.getProperty("FUSE_SECURITY_CUSTOMERS"),customers)),demo);
        add(env,"DEVELOPER","developer",new Actor("developer-01","DEVELOPER",Set.of()),demo);
        String service=env.getProperty("FUSE_SERVICE_TOKEN",env.getProperty("fuse.service-token",""));
        if(demo && validToken(service)) register(service,new Actor("kyc-service","KYC_SERVICE",Set.of()));
    }
    private void add(Environment env,String suffix,String property,Actor actor,boolean demo) {
        String token=env.getProperty("FUSE_DEV_"+suffix+"_TOKEN",env.getProperty("FUSE_"+suffix+"_TOKEN",env.getProperty("fuse.auth."+property+"-token","")));
        if(token==null||token.isBlank()||token.equals("CHANGE_ME"))return;
        if(!demo)throw new IllegalStateException("Development authentication requires an exclusively demo/test profile");
        register(token,actor);
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
    public synchronized void register(String token,Actor actor) {
        if(!validToken(token))throw new IllegalStateException("Development tokens must encode at least 32 random bytes");
        byte[] digest=digest(token);
        if(entries.stream().anyMatch(e->MessageDigest.isEqual(e.digest(),digest)))throw new IllegalStateException("Authentication tokens must be distinct across actors");
        Instant now=clock.instant();entries.add(new Entry(digest,new Registration(actor,now,now.plusSeconds(ttl),Status.ACTIVE)));
    }
    public synchronized Actor resolve(String token) {
        if(token==null || token.length()>256)return null;
        byte[] digest=digest(token);Actor match=null;Instant now=clock.instant();
        for(Entry entry:entries) {
            boolean same=MessageDigest.isEqual(entry.digest(),digest);Registration r=entry.registration();
            if(same && r.status()==Status.ACTIVE && !now.isBefore(r.createdAt()) && now.isBefore(r.expiresAt()))match=r.actor();
        }
        return match;
    }
    public synchronized void revoke(String actorId) { replace(actorId,null,true); }
    public synchronized void updateScope(String actorId,Set<String> customers) { replace(actorId,Set.copyOf(customers),false); }
    private void replace(String actorId,Set<String> customers,boolean revoke) {
        for(int i=0;i<entries.size();i++) {
            Entry e=entries.get(i);Registration r=e.registration();
            if(r.actor().actorId().equals(actorId))entries.set(i,new Entry(e.digest(),new Registration(customers==null?r.actor():new Actor(actorId,r.actor().role(),customers),r.createdAt(),r.expiresAt(),revoke?Status.REVOKED:r.status())));
        }
    }
    private static byte[] digest(String value) {
        try{return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));}
        catch(NoSuchAlgorithmException impossible){throw new IllegalStateException(impossible);}
    }
    private static Set<String> scope(String source,Set<String> fallback) {
        return source==null?fallback:Arrays.stream(source.split(",")).map(String::trim).filter(s->!s.isEmpty()).collect(Collectors.toUnmodifiableSet());
    }
}
