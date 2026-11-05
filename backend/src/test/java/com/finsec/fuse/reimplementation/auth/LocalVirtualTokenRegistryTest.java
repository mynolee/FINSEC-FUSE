package com.finsec.fuse.reimplementation.auth;

import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.auth.LocalVirtualTokenRegistry.*;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic in-process registry boundaries; no entropy, real credential, storage or issuance. */
final class LocalVirtualTokenRegistryTest {
    private static final Instant START=Instant.parse("2026-11-05T00:00:00Z"),END=START.plusSeconds(60);
    private static final UUID TOKEN=new UUID(1,1),PRINCIPAL=new UUID(2,2);
    private static byte[] fp(int value){byte[] b=new byte[32];Arrays.fill(b,(byte)value);return b;}
    private static Credential credential(UUID token,byte[] fingerprint,long revision){
        return new Credential(token,PRINCIPAL,Status.ACTIVE,revision,START,END,7,fingerprint);
    }
    @Test void suppliedRawMaterialCanonicalLookupReturnsOnlyFingerprintCredential(){
        byte[] raw=new byte[32];var material=TokenMaterialCodec.encode(raw);
        var registry=new LocalVirtualTokenRegistry(2);var entry=credential(TOKEN,material.fingerprint(),0);
        registry.registerPrepared(entry);var found=registry.lookupCanonical(material.bearer(),START);
        assertEquals(LookupStatus.FOUND,found.status());assertSame(entry,found.credential());
        assertEquals(PRINCIPAL,found.credential().principalId());assertEquals(7,found.credential().bindingRevision());
        assertArrayEquals(material.fingerprint(),found.credential().fingerprint());
        assertFalse(registry.toString().contains(material.bearer()));
        assertEquals("LocalVirtualCredential[REDACTED]",entry.toString());
        assertEquals("LocalVirtualCredentialLookup[REDACTED]",found.toString());
    }
    @Test void invalidOrNoncanonicalBearerNeverBecomesFingerprintLookupSuccess(){
        var material=TokenMaterialCodec.encode(new byte[32]);var registry=new LocalVirtualTokenRegistry(1);
        registry.registerPrepared(credential(TOKEN,material.fingerprint(),0));
        for(String value:new String[]{"",material.bearer()+"="," "+material.bearer(),"+".repeat(43),"A".repeat(42)+"B"}){
            assertEquals(LookupStatus.UNAUTHENTICATED,registry.lookupCanonical(value,START).status());
        }
        assertEquals(LookupStatus.UNAUTHENTICATED,registry.lookupCanonical(null,START).status());
        assertEquals(1,registry.size());
    }
    @Test void exactIssuedBoundaryAcceptedAndExpiryEqualityRejected(){
        var registry=new LocalVirtualTokenRegistry(1);var entry=credential(TOKEN,fp(1),4);registry.registerPrepared(entry);
        assertEquals(LookupStatus.UNAUTHENTICATED,registry.lookupFingerprint(fp(1),START.minusNanos(1)).status());
        assertSame(entry,registry.lookupFingerprint(fp(1),START).credential());
        assertSame(entry,registry.lookupFingerprint(fp(1),END.minusNanos(1)).credential());
        assertEquals(LookupStatus.UNAUTHENTICATED,registry.lookupFingerprint(fp(1),END).status());
        assertFalse(registry.stillCurrent(entry,END));
    }
    @Test void revocationRequiresExactRevisionAndNeverReactivatesOrReusesFingerprint(){
        var registry=new LocalVirtualTokenRegistry(2);var entry=credential(TOKEN,fp(1),4);registry.registerPrepared(entry);
        assertEquals(RevokeStatus.REVISION_CONFLICT,registry.revoke(TOKEN,3).status());assertTrue(registry.stillCurrent(entry,START));
        assertEquals(new Revocation(RevokeStatus.REVOKED,5),registry.revoke(TOKEN,4));
        assertFalse(registry.stillCurrent(entry,START));assertEquals(LookupStatus.UNAUTHENTICATED,registry.lookupFingerprint(fp(1),START).status());
        assertEquals(RevokeStatus.REVISION_CONFLICT,registry.revoke(TOKEN,4).status());
        assertEquals(RevokeStatus.ALREADY_REVOKED,registry.revoke(TOKEN,5).status());
        assertThrows(IllegalStateException.class,()->registry.registerPrepared(credential(new UUID(3,3),fp(1),0)));
        assertThrows(IllegalStateException.class,()->registry.registerPrepared(credential(TOKEN,fp(2),0)));
        assertEquals(1,registry.size());
    }
    @Test void revisionOverflowRefusesMutationAndMissingTokenIsExplicit(){
        var registry=new LocalVirtualTokenRegistry(1);var entry=credential(TOKEN,fp(1),Long.MAX_VALUE);registry.registerPrepared(entry);
        assertEquals(new Revocation(RevokeStatus.REVISION_EXHAUSTED,Long.MAX_VALUE),registry.revoke(TOKEN,Long.MAX_VALUE));
        assertTrue(registry.stillCurrent(entry,START));
        assertEquals(new Revocation(RevokeStatus.NOT_FOUND,-1),registry.revoke(new UUID(8,8),0));
    }
    @Test void fingerprintAndCredentialSnapshotsAreDefensiveAndCapacityNeverEvicts(){
        byte[] original=fp(1);var entry=credential(TOKEN,original,0);original[0]=9;
        byte[] returned=entry.fingerprint();returned[0]=8;
        var registry=new LocalVirtualTokenRegistry(1);registry.registerPrepared(entry);
        assertSame(entry,registry.lookupFingerprint(fp(1),START).credential());
        assertThrows(IllegalStateException.class,()->registry.registerPrepared(credential(new UUID(3,3),fp(2),0)));
        assertTrue(registry.stillCurrent(entry,START));assertEquals(1,registry.size());
        var equalData=credential(TOKEN,fp(1),0);assertFalse(registry.stillCurrent(equalData,START));
    }
    @Test void sealedReferenceCurrentTupleRevalidatesWithoutBearerOrCreatingRecords(){
        var registry=new LocalVirtualTokenRegistry(2);var entry=credential(TOKEN,fp(1),4);registry.registerPrepared(entry);
        assertSame(entry,registry.revalidateReference(TOKEN,PRINCIPAL,4,7,START,END,START).credential());
        assertEquals(LookupStatus.UNAUTHENTICATED,registry.revalidateReference(TOKEN,new UUID(9,9),4,7,START,END,START).status());
        assertEquals(LookupStatus.UNAUTHENTICATED,registry.revalidateReference(TOKEN,PRINCIPAL,3,7,START,END,START).status());
        assertEquals(LookupStatus.UNAUTHENTICATED,registry.revalidateReference(TOKEN,PRINCIPAL,4,8,START,END,START).status());
        assertEquals(LookupStatus.UNAUTHENTICATED,registry.revalidateReference(TOKEN,PRINCIPAL,4,7,START.plusNanos(1),END,START).status());
        assertEquals(LookupStatus.UNAUTHENTICATED,registry.revalidateReference(TOKEN,PRINCIPAL,4,7,START,END.plusNanos(1),START).status());
        assertEquals(LookupStatus.UNAUTHENTICATED,registry.revalidateReference(new UUID(8,8),PRINCIPAL,4,7,START,END,START).status());
        assertEquals(1,registry.size());assertTrue(registry.stillCurrent(entry,START));
    }
    @Test void referenceSnapshotCannotSurviveRevocationOrExpiryAndNeverRenews(){
        var registry=new LocalVirtualTokenRegistry(1);registry.registerPrepared(credential(TOKEN,fp(1),4));
        assertEquals(LookupStatus.UNAUTHENTICATED,registry.revalidateReference(TOKEN,PRINCIPAL,4,7,START,END,END).status());
        assertEquals(RevokeStatus.REVOKED,registry.revoke(TOKEN,4).status());
        assertEquals(LookupStatus.UNAUTHENTICATED,registry.revalidateReference(TOKEN,PRINCIPAL,4,7,START,END,START).status());
        assertEquals(LookupStatus.UNAUTHENTICATED,registry.revalidateReference(TOKEN,PRINCIPAL,5,7,START,END,START).status());
        assertEquals(RevokeStatus.ALREADY_REVOKED,registry.revoke(TOKEN,5).status());assertEquals(1,registry.size());
        assertThrows(IllegalArgumentException.class,()->registry.revalidateReference(TOKEN,PRINCIPAL,-1,7,START,END,START));
    }
    @Test void onlyCanonicalBearerMintsSealedRegistryIdentityEvidence(){
        var material=TokenMaterialCodec.encode(new byte[32]);var registry=new LocalVirtualTokenRegistry(1);
        registry.registerPrepared(credential(TOKEN,material.fingerprint(),4));
        var proof=registry.admitCanonical(material.bearer(),START);assertNotNull(proof);
        assertTrue(proof.issuedBy(registry));assertFalse(proof.issuedBy(new LocalVirtualTokenRegistry(1)));
        assertFalse(proof.issuedBy(null));assertEquals(TOKEN,proof.reference().tokenId());
        assertEquals(PRINCIPAL,proof.reference().principalId());assertEquals(4,proof.reference().tokenRevision());
        assertEquals(7,proof.reference().bindingRevision());assertEquals(START,proof.reference().issuedAt());assertEquals(END,proof.reference().expiresAt());
        assertEquals("LocalVirtualCredentialEvidence[REDACTED]",proof.toString());
        assertTrue(LocalVirtualAdmissionContext.CredentialEvidence.class.isSealed());
        assertArrayEquals(new Class<?>[]{LocalVirtualTokenRegistry.Evidence.class},LocalVirtualAdmissionContext.CredentialEvidence.class.getPermittedSubclasses());
        for(var constructor:LocalVirtualTokenRegistry.Evidence.class.getDeclaredConstructors())
            assertTrue(java.lang.reflect.Modifier.isPrivate(constructor.getModifiers()));
        var data=registry.revalidateReference(TOKEN,PRINCIPAL,4,7,START,END,START);
        assertEquals(LookupStatus.FOUND,data.status());
        assertFalse(LocalVirtualAdmissionContext.CredentialEvidence.class.isInstance(data));
        assertFalse(LocalVirtualAdmissionContext.CredentialEvidence.class.isInstance(registry.lookupFingerprint(material.fingerprint(),START)));
    }
    @Test void malformedExpiredAndRevokedBearersCannotMintAndOldEvidenceIsNotCurrentProof(){
        var material=TokenMaterialCodec.encode(new byte[32]);var registry=new LocalVirtualTokenRegistry(1);
        registry.registerPrepared(credential(TOKEN,material.fingerprint(),4));
        assertNull(registry.admitCanonical(material.bearer()+"=",START));
        assertNull(registry.admitCanonical(material.bearer(),START.minusNanos(1)));
        assertNull(registry.admitCanonical(material.bearer(),END));
        var proof=registry.admitCanonical(material.bearer(),START);assertNotNull(proof);
        registry.revoke(TOKEN,4);assertNull(registry.admitCanonical(material.bearer(),START));
        var ref=proof.reference();
        assertEquals(LookupStatus.UNAUTHENTICATED,registry.revalidateReference(ref.tokenId(),ref.principalId(),ref.tokenRevision(),ref.bindingRevision(),ref.issuedAt(),ref.expiresAt(),START).status());
        assertTrue(proof.issuedBy(registry)); // Origin remains true; current context must still revalidate.
        assertThrows(IllegalArgumentException.class,()->registry.admitCanonical(material.bearer(),null));
    }
    @Test void invalidShapesUseFixedErrorsAndNoPreparedRevokedInsertion(){
        assertThrows(IllegalArgumentException.class,()->new LocalVirtualTokenRegistry(0));
        var ex=assertThrows(IllegalArgumentException.class,()->new Credential(TOKEN,PRINCIPAL,Status.ACTIVE,-1,START,END,0,fp(1)));
        assertEquals("INVALID_LOCAL_VIRTUAL_CREDENTIAL",ex.getMessage());assertNull(ex.getCause());
        assertThrows(IllegalArgumentException.class,()->new Credential(TOKEN,PRINCIPAL,Status.ACTIVE,0,START,START,0,fp(1)));
        assertThrows(IllegalArgumentException.class,()->new Credential(TOKEN,PRINCIPAL,Status.ACTIVE,0,START,END,0,new byte[31]));
        var registry=new LocalVirtualTokenRegistry(1);
        assertThrows(IllegalArgumentException.class,()->registry.registerPrepared(new Credential(TOKEN,PRINCIPAL,Status.REVOKED,1,START,END,0,fp(1))));
        assertThrows(IllegalArgumentException.class,()->registry.registerPrepared(null));assertEquals(0,registry.size());
    }
}
