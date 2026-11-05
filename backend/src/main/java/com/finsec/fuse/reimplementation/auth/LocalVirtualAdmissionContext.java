package com.finsec.fuse.reimplementation.auth;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.simulation.SimulationAccess.Operation;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Server-owned per-thread admission; never inherited, serialized, or reconstructed from ActorRef alone. */
public final class LocalVirtualAdmissionContext {
    public enum CredentialState { ACTIVE, REVOKED, ABSENT, UNCONFIRMED }
    public enum Code { UNAUTHENTICATED, FORBIDDEN, UNAVAILABLE }
    public static final class Failure extends RuntimeException {
        private final Code code;
        private Failure(Code code){super(code.name(),null,false,false);this.code=code;}
        public Code code(){return code;}
    }
    public record CredentialReference(UUID tokenId,UUID principalId,long tokenRevision,long bindingRevision,
            Instant issuedAt,Instant expiresAt){
        public CredentialReference {
            if(tokenId==null||principalId==null||tokenRevision<0||bindingRevision<0||issuedAt==null||expiresAt==null
                    ||!issuedAt.isBefore(expiresAt))throw new IllegalArgumentException("INVALID_CREDENTIAL_REFERENCE");
        }
        @Override public String toString(){return "CredentialReference[REDACTED]";}
    }
    /** Only the registry's private-constructor implementation can carry canonical bearer evidence. */
    public sealed interface CredentialEvidence permits LocalVirtualTokenRegistry.Evidence {
        CredentialReference reference();
        boolean issuedBy(Object expectedIssuer);
    }
    /** Supplied only by the trusted verifier; ACTIVE requires a coherent current principal. */
    public record VerifiedSnapshot(CredentialReference credential,CredentialState state,LocalVirtualPrincipal principal){
        public VerifiedSnapshot {Objects.requireNonNull(credential);Objects.requireNonNull(state);}
        @Override public String toString(){return "VerifiedLocalAdmission[REDACTED]";}
    }
    @FunctionalInterface public interface Verifier {
        /** Re-read the actual server-owned credential/principal state for this new admission; no request assertions. */
        VerifiedSnapshot current(CredentialReference requested,Instant now);
    }
    private final Verifier verifier;
    private final Object credentialIssuer;
    private final ThreadLocal<Admission> local=new ThreadLocal<>();
    public LocalVirtualAdmissionContext(Verifier verifier,Object credentialIssuer){
        this.verifier=Objects.requireNonNull(verifier);this.credentialIssuer=Objects.requireNonNull(credentialIssuer);
    }

    public Admission openRequest(CredentialEvidence evidence,Instant now){
        if(evidence==null||now==null||!evidence.issuedBy(credentialIssuer))throw fail(Code.UNAUTHENTICATED);
        var requested=evidence.reference();
        if(local.get()!=null)throw fail(Code.UNAVAILABLE);
        try{
            var snapshot=verifier.current(requested,now);
            if(snapshot==null||snapshot.state()==CredentialState.UNCONFIRMED)throw fail(Code.UNAVAILABLE);
            if(snapshot.state()!=CredentialState.ACTIVE)throw fail(Code.UNAUTHENTICATED);
            var current=snapshot.credential();var principal=snapshot.principal();
            if(!current.equals(requested))throw fail(Code.UNAUTHENTICATED);
            if(now.isBefore(current.issuedAt())||!now.isBefore(current.expiresAt()))throw fail(Code.UNAUTHENTICATED);
            if(principal==null||principal.status()==LocalVirtualPrincipal.Status.UNCONFIRMED)throw fail(Code.UNAVAILABLE);
            if(!principal.principalId().equals(current.principalId()))throw fail(Code.UNAVAILABLE);
            if(principal.status()!=LocalVirtualPrincipal.Status.ACTIVE||principal.bindingRevision()!=current.bindingRevision())throw fail(Code.UNAUTHENTICATED);
            var admission=new Admission(current,principal,now,Thread.currentThread());
            local.set(admission);return admission;
        }catch(Failure fixed){throw fixed;}
        catch(RuntimeException unavailable){throw fail(Code.UNAVAILABLE);}
    }
    /** null means no server admission exists on this thread. */
    public Admission current(){return local.get();}
    public LocalVirtualAccessPolicy.Decision authorizeSameActor(ActorRef actor,Operation operation,UUID workflowId,String customerId){
        var admission=current();if(admission==null)throw fail(Code.UNAUTHENTICATED);
        if(actor==null||!admission.principal().actorAlias().equals(actor.actorId()))return LocalVirtualAccessPolicy.Decision.FORBIDDEN;
        return admission.authorize(operation,workflowId,customerId);
    }
    public final class Admission implements AutoCloseable {
        private final CredentialReference credential;
        private final LocalVirtualPrincipal principal;
        private final Instant admittedAt;
        private final Thread owner;
        private Operation operation;
        private UUID authorizedWorkflow;
        private String authorizedCustomer;
        private boolean scopeBound;
        private boolean closed;
        private Admission(CredentialReference credential,LocalVirtualPrincipal principal,Instant admittedAt,Thread owner){
            this.credential=credential;this.principal=principal;this.admittedAt=admittedAt;this.owner=owner;
        }
        private void live(){if(Thread.currentThread()!=owner||closed||local.get()!=this)throw fail(Code.UNAVAILABLE);}
        public CredentialReference credential(){live();return credential;}
        public LocalVirtualPrincipal principal(){live();return principal;}
        public Instant admittedAt(){live();return admittedAt;}
        public ActorRef actor(){live();return new ActorRef(principal.actorAlias());}
        public LocalVirtualAccessPolicy.Decision authorize(Operation requested,UUID workflowId,String customerId){
            live();if(requested==null)return LocalVirtualAccessPolicy.Decision.FORBIDDEN;
            if(operation!=null&&operation!=requested)return LocalVirtualAccessPolicy.Decision.FORBIDDEN;
            operation=requested;
            if(scopeBound&&(!Objects.equals(authorizedWorkflow,workflowId)
                    ||(customerId!=null&&!Objects.equals(authorizedCustomer,customerId))))
                return LocalVirtualAccessPolicy.Decision.FORBIDDEN;
            var decision=LocalVirtualAccessPolicy.assess(principal,requested,workflowId,customerId);
            if(decision==LocalVirtualAccessPolicy.Decision.ALLOW&&!scopeBound){
                authorizedWorkflow=workflowId;
                authorizedCustomer=customerId!=null?customerId:principal.workflowAssignments().get(workflowId);
                scopeBound=true;
            }
            return decision;
        }
        @Override public void close(){
            if(Thread.currentThread()!=owner)throw fail(Code.UNAVAILABLE);
            if(closed)return;
            if(local.get()!=this)throw fail(Code.UNAVAILABLE);
            closed=true;local.remove();
        }
        @Override public String toString(){return "LocalVirtualAdmission[REDACTED]";}
    }
    private static Failure fail(Code code){return new Failure(code);}
    @Override public String toString(){return "LocalVirtualAdmissionContext[REDACTED]";}
}
