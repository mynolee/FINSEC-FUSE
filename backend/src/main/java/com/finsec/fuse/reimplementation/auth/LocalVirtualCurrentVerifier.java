package com.finsec.fuse.reimplementation.auth;

import java.time.Instant;
import java.util.Objects;
import static com.finsec.fuse.reimplementation.auth.LocalVirtualAdmissionContext.*;

/** Current in-process credential/principal join. No bearer minting or resource-ownership authority. */
public final class LocalVirtualCurrentVerifier implements LocalVirtualAdmissionContext.Verifier {
    private final LocalVirtualTokenRegistry credentials;
    private final LocalVirtualPrincipalRegistry principals;
    public LocalVirtualCurrentVerifier(LocalVirtualTokenRegistry credentials,LocalVirtualPrincipalRegistry principals){
        this.credentials=Objects.requireNonNull(credentials);this.principals=Objects.requireNonNull(principals);
    }
    /** Exact prepared graph identity; values or equal snapshots cannot attest another registry. */
    boolean boundTo(LocalVirtualTokenRegistry expectedCredentials,LocalVirtualPrincipalRegistry expectedPrincipals){
        return credentials==expectedCredentials && principals==expectedPrincipals;
    }
    @Override public VerifiedSnapshot current(CredentialReference requested,Instant now){
        if(requested==null || now==null)throw new IllegalArgumentException("INVALID_CURRENT_ADMISSION_INPUT",null);
        try {
            var found=credentials.revalidateReference(requested.tokenId(),requested.principalId(),requested.tokenRevision(),
                    requested.bindingRevision(),requested.issuedAt(),requested.expiresAt(),now);
            if(found.status()!=LocalVirtualTokenRegistry.LookupStatus.FOUND)return state(requested,CredentialState.ABSENT,null);
            var credential=found.credential();
            var principal=principals.findCurrent(credential.principalId());
            if(principal==null || principal.status()==LocalVirtualPrincipal.Status.UNCONFIRMED)
                return state(requested,CredentialState.UNCONFIRMED,principal);
            if(!principal.principalId().equals(requested.principalId()))return state(requested,CredentialState.UNCONFIRMED,null);
            if(principal.status()!=LocalVirtualPrincipal.Status.ACTIVE || principal.bindingRevision()!=requested.bindingRevision())
                return state(requested,CredentialState.ABSENT,principal);
            if(principals.findCurrentAlias(principal.actorAlias())!=principal)return state(requested,CredentialState.UNCONFIRMED,null);
            // Independent registries are rechecked; this is not an atomic revocation/domain-commit transaction.
            if(!credentials.stillCurrent(credential,now) || principals.findCurrent(principal.principalId())!=principal)
                return state(requested,CredentialState.UNCONFIRMED,null);
            return state(requested,CredentialState.ACTIVE,principal);
        }catch(RuntimeException unavailable){return state(requested,CredentialState.UNCONFIRMED,null);}
    }
    private static VerifiedSnapshot state(CredentialReference reference,CredentialState state,LocalVirtualPrincipal principal){
        return new VerifiedSnapshot(reference,state,principal);
    }
    @Override public String toString(){return "LocalVirtualCurrentVerifier[REDACTED]";}
}
