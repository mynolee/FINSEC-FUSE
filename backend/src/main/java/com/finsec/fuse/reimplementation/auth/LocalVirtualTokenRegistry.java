package com.finsec.fuse.reimplementation.auth;

import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/** Bounded in-process fingerprint registry. No entropy, persistence, administration or role authority. */
public final class LocalVirtualTokenRegistry {
    public enum Status { ACTIVE, REVOKED }
    public enum LookupStatus { FOUND, UNAUTHENTICATED }
    public enum RevokeStatus { REVOKED, ALREADY_REVOKED, NOT_FOUND, REVISION_CONFLICT, REVISION_EXHAUSTED }
    public static final class Credential {
        private final UUID tokenId, principalId;
        private final Status status;
        private final long revision, bindingRevision;
        private final Instant issuedAt, expiresAt;
        private final byte[] fingerprint;
        public Credential(UUID tokenId, UUID principalId, Status status, long revision,
                Instant issuedAt, Instant expiresAt, long bindingRevision, byte[] fingerprint) {
            if (tokenId==null || principalId==null || status==null || revision<0 || bindingRevision<0
                    || issuedAt==null || expiresAt==null || !expiresAt.isAfter(issuedAt)
                    || fingerprint==null || fingerprint.length!=32) throw invalid();
            this.tokenId=tokenId; this.principalId=principalId; this.status=status; this.revision=revision;
            this.issuedAt=issuedAt; this.expiresAt=expiresAt; this.bindingRevision=bindingRevision;
            this.fingerprint=fingerprint.clone();
        }
        public UUID tokenId(){return tokenId;}
        public UUID principalId(){return principalId;}
        public Status status(){return status;}
        public long revision(){return revision;}
        public long bindingRevision(){return bindingRevision;}
        public Instant issuedAt(){return issuedAt;}
        public Instant expiresAt(){return expiresAt;}
        public byte[] fingerprint(){return fingerprint.clone();}
        @Override public String toString(){return "LocalVirtualCredential[REDACTED]";}
    }
    /** Only this registry's canonical bearer path can construct the sealed possession evidence. */
    public static final class Evidence implements LocalVirtualAdmissionContext.CredentialEvidence {
        private final LocalVirtualAdmissionContext.CredentialReference reference;
        private final LocalVirtualTokenRegistry issuer;
        private Evidence(LocalVirtualAdmissionContext.CredentialReference reference,LocalVirtualTokenRegistry issuer){
            this.reference=reference;this.issuer=issuer;
        }
        @Override public LocalVirtualAdmissionContext.CredentialReference reference(){return reference;}
        @Override public boolean issuedBy(Object expectedIssuer){return issuer==expectedIssuer;}
        @Override public String toString(){return "LocalVirtualCredentialEvidence[REDACTED]";}
    }
    public record Lookup(LookupStatus status, Credential credential) {
        public Lookup {
            if(status==null || (status==LookupStatus.FOUND)!=(credential!=null))throw invalid();
        }
        @Override public String toString(){return "LocalVirtualCredentialLookup[REDACTED]";}
    }
    public record Revocation(RevokeStatus status, long currentRevision) {
        public Revocation {if(status==null || currentRevision< -1)throw invalid();}
    }
    private final int maximumRecords;
    private final Map<UUID,Credential> records=new LinkedHashMap<>();
    private final Map<String,UUID> fingerprints=new LinkedHashMap<>();
    public LocalVirtualTokenRegistry(int maximumRecords){
        if(maximumRecords<1)throw invalid();this.maximumRecords=maximumRecords;
    }
    /** Caller must independently authorize administration; this method only commits prepared data in memory. */
    public synchronized void registerPrepared(Credential credential){
        if(credential==null)throw invalid();
        if(credential.status()!=Status.ACTIVE)throw invalid();
        String key=key(credential.fingerprint);
        if(records.containsKey(credential.tokenId()) || fingerprints.containsKey(key))throw conflict();
        if(records.size()>=maximumRecords)throw unavailable();
        records.put(credential.tokenId(),credential);fingerprints.put(key,credential.tokenId());
    }
    /** Permanent exact-token revision CAS. Retains fingerprint indexes even after revocation. */
    public synchronized Revocation revoke(UUID tokenId,long expectedRevision){
        if(tokenId==null || expectedRevision<0)throw invalid();
        var old=records.get(tokenId);
        if(old==null)return new Revocation(RevokeStatus.NOT_FOUND,-1);
        if(old.revision()!=expectedRevision)return new Revocation(RevokeStatus.REVISION_CONFLICT,old.revision());
        if(old.status()==Status.REVOKED)return new Revocation(RevokeStatus.ALREADY_REVOKED,old.revision());
        if(old.revision()==Long.MAX_VALUE)return new Revocation(RevokeStatus.REVISION_EXHAUSTED,old.revision());
        var next=new Credential(old.tokenId(),old.principalId(),Status.REVOKED,old.revision()+1,
                old.issuedAt(),old.expiresAt(),old.bindingRevision(),old.fingerprint);
        records.put(tokenId,next);return new Revocation(RevokeStatus.REVOKED,next.revision());
    }
    /** Strict canonical32-byte bearer admission. Does not validate the current principal, binding or scope. */
    public Lookup lookupCanonical(String bearer,Instant now){
        if(now==null)throw invalid();
        if(bearer==null || !bearer.matches("[A-Za-z0-9_-]{43}"))return absent();
        final byte[] raw;
        try{raw=Base64.getUrlDecoder().decode(bearer);}
        catch(IllegalArgumentException malformed){return absent();}
        if(raw.length!=32 || !Base64.getUrlEncoder().withoutPadding().encodeToString(raw).equals(bearer))return absent();
        // Standard named SHA-256 codec, no entropy, provider fallback or raw bearer retention.
        final byte[] fingerprint;
        try{fingerprint=TokenMaterialCodec.encode(raw).fingerprint();}
        catch(RuntimeException failure){throw unavailable();}
        return lookupFingerprint(fingerprint,now);
    }
    /** Canonical bearer possession evidence only; current principal/scope checks still belong to admission. */
    public synchronized LocalVirtualAdmissionContext.CredentialEvidence admitCanonical(String bearer,Instant now){
        var found=lookupCanonical(bearer,now);
        if(found.status()!=LookupStatus.FOUND)return null;
        var c=found.credential();
        var reference=new LocalVirtualAdmissionContext.CredentialReference(c.tokenId(),c.principalId(),
                c.revision(),c.bindingRevision(),c.issuedAt(),c.expiresAt());
        return new Evidence(reference,this);
    }
    /** Trusted adapter seam for an already computed raw32 SHA-256 fingerprint, never encoded-bearer hash. */
    public synchronized Lookup lookupFingerprint(byte[] fingerprint,Instant now){
        if(fingerprint==null || fingerprint.length!=32 || now==null)throw invalid();
        var id=fingerprints.get(key(fingerprint));
        if(id==null)return absent();
        var credential=records.get(id);
        if(credential==null || !key(credential.fingerprint).equals(key(fingerprint)))throw unavailable();
        if(credential.status()!=Status.ACTIVE || now.isBefore(credential.issuedAt()) || !now.isBefore(credential.expiresAt()))return absent();
        return new Lookup(LookupStatus.FOUND,credential);
    }
    /** Read-only revalidation of a server-sealed reference; reference data alone never authenticates. */
    public synchronized Lookup revalidateReference(UUID tokenId,UUID principalId,long tokenRevision,
            long bindingRevision,Instant issuedAt,Instant expiresAt,Instant now){
        if(tokenId==null || principalId==null || tokenRevision<0 || bindingRevision<0
                || issuedAt==null || expiresAt==null || !expiresAt.isAfter(issuedAt) || now==null)throw invalid();
        var actual=records.get(tokenId);
        if(actual==null)return absent();
        if(!tokenId.equals(fingerprints.get(key(actual.fingerprint))))throw unavailable();
        if(!actual.principalId().equals(principalId) || actual.revision()!=tokenRevision
                || actual.bindingRevision()!=bindingRevision || !actual.issuedAt().equals(issuedAt)
                || !actual.expiresAt().equals(expiresAt))return absent();
        return lookupFingerprint(actual.fingerprint,now);
    }
    /** Snapshot recheck for a new admission; no atomic revocation-versus-domain-commit guarantee. */
    public synchronized boolean stillCurrent(Credential snapshot,Instant now){
        if(snapshot==null || now==null)throw invalid();
        var actual=records.get(snapshot.tokenId());
        return actual==snapshot && lookupFingerprint(snapshot.fingerprint,now).status()==LookupStatus.FOUND;
    }
    public synchronized int size(){return records.size();}
    private static String key(byte[] fingerprint){return Base64.getEncoder().encodeToString(fingerprint);}
    private static Lookup absent(){return new Lookup(LookupStatus.UNAUTHENTICATED,null);}
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("INVALID_LOCAL_VIRTUAL_CREDENTIAL",null);}
    private static IllegalStateException conflict(){return new IllegalStateException("LOCAL_VIRTUAL_CREDENTIAL_CONFLICT",null);}
    private static IllegalStateException unavailable(){return new IllegalStateException("LOCAL_VIRTUAL_REGISTRY_UNAVAILABLE",null);}
    @Override public String toString(){return "LocalVirtualTokenRegistry[REDACTED]";}
}
