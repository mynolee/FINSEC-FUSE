package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.WorkflowHttpController;
import com.finsec.fuse.reimplementation.auth.LocalVirtualAdmissionContext;
import com.finsec.fuse.reimplementation.auth.LocalVirtualTokenRegistry;
import com.finsec.fuse.reimplementation.http.LocalVirtualAuthenticationFilter;
import com.finsec.fuse.reimplementation.http.LocalVirtualHttpActors;
import com.finsec.fuse.reimplementation.http.PublicHttpErrors;
import com.finsec.fuse.reimplementation.simulation.SimulationAccess;
import com.finsec.fuse.reimplementation.simulation.SimulationApiController;
import java.time.Clock;

/** Explicit local authentication bundle. No credential population, current-principal default or automatic activation. */
public final class PreparedLocalVirtualSecurity {
    private final LocalVirtualAdmissionContext context;
    private final LocalVirtualHttpActors actors;
    private final SimulationAccess.Authority authority;
    private final LocalVirtualAuthenticationFilter filter;
    private final Clock clock;
    private PreparedLocalVirtualSecurity(LocalVirtualTokenRegistry tokens,
            LocalVirtualAdmissionContext.Verifier verifier,Clock clock){
        if(tokens==null||verifier==null||clock==null)throw missing();
        this.clock=clock;
        context=new LocalVirtualAdmissionContext((reference,now)->{
            var before=tokens.revalidateReference(reference.tokenId(),reference.principalId(),reference.tokenRevision(),
                    reference.bindingRevision(),reference.issuedAt(),reference.expiresAt(),now);
            if(before.status()!=LocalVirtualTokenRegistry.LookupStatus.FOUND)return absent(reference);
            var supplied=verifier.current(reference,now);
            var after=tokens.revalidateReference(reference.tokenId(),reference.principalId(),reference.tokenRevision(),
                    reference.bindingRevision(),reference.issuedAt(),reference.expiresAt(),now);
            if(after.status()!=LocalVirtualTokenRegistry.LookupStatus.FOUND)return absent(reference);
            return supplied;
        },tokens);
        actors=new LocalVirtualHttpActors(context);
        authority=actors.authority();
        filter=new LocalVirtualAuthenticationFilter(tokens,context,clock,new PublicHttpErrors());
    }
    private PreparedLocalVirtualSecurity(LocalVirtualTokenRegistry tokens,
            com.finsec.fuse.reimplementation.auth.LocalVirtualPrincipalRegistry principals,Clock clock){
        if(tokens==null||principals==null||clock==null)throw missing();
        this.clock=clock;
        context=new LocalVirtualAdmissionContext(
                new com.finsec.fuse.reimplementation.auth.LocalVirtualCurrentVerifier(tokens,principals),tokens);
        actors=new LocalVirtualHttpActors(context);
        authority=actors.authority();
        filter=new LocalVirtualAuthenticationFilter(tokens,context,clock,new PublicHttpErrors());
    }
    /** Explicit concrete same-registry graph; no wrapper provenance assertion or default principals. */
    public static PreparedLocalVirtualSecurity prepareCurrentRegistries(LocalVirtualTokenRegistry tokens,
            com.finsec.fuse.reimplementation.auth.LocalVirtualPrincipalRegistry principals,Clock clock){
        return new PreparedLocalVirtualSecurity(tokens,principals,clock);
    }
    public static PreparedLocalVirtualSecurity prepare(LocalVirtualTokenRegistry tokens,
            LocalVirtualAdmissionContext.Verifier currentVerifier,Clock clock){
        return new PreparedLocalVirtualSecurity(tokens,currentVerifier,clock);
    }
    private static LocalVirtualAdmissionContext.VerifiedSnapshot absent(LocalVirtualAdmissionContext.CredentialReference reference){
        return new LocalVirtualAdmissionContext.VerifiedSnapshot(reference,LocalVirtualAdmissionContext.CredentialState.ABSENT,null);
    }
    public LocalVirtualHttpActors actors(){return actors;}
    public SimulationAccess.Authority authority(){return authority;}
    public LocalVirtualAdmissionContext context(){return context;}
    public LocalVirtualAuthenticationFilter authenticationFilter(){return filter;}
    public Clock clock(){return clock;}
    /** Reject unrelated permissive HTTP/domain ports in a graph labeled local-auth configured. */
    public void requireBindings(SimulationAccess.Authority authority,WorkflowHttpController.ActorPort startResume,
            SimulationApiController.HttpActors others,Clock clock){
        if(authority!=this.authority||startResume!=actors||others!=actors||clock!=this.clock)throw missing();
    }
    private static IllegalStateException missing(){return new IllegalStateException("CONFIGURATION_REQUIRED",null);}
    @Override public String toString(){return "PreparedLocalVirtualSecurity[REDACTED]";}
}
