package com.finsec.fuse.reimplementation.auth;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.persistence.ActionJournal.ActionIdentity;
import com.finsec.fuse.reimplementation.simulation.SimulationAccess.Operation;
import com.finsec.fuse.reimplementation.simulation.VirtualExperimentService;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import static com.finsec.fuse.reimplementation.auth.LocalVirtualAdmissionContext.*;

/** Exact experiment-only server dispatch registrations; never bearer storage or an owner identity rewrite. */
public final class LocalVirtualOwnerDelegationRegistry {
    public enum Code { UNAUTHENTICATED, FORBIDDEN, UNAVAILABLE, CONFLICT }
    public static final class Failure extends RuntimeException {
        private final Code code;
        private Failure(Code code){super(code.name(),null,false,false);this.code=code;}
        public Code code(){return code;}
    }
    public enum Status { ACTIVE, REVOKED }
    public enum RevokeStatus { REVOKED, ALREADY_REVOKED, NOT_FOUND, REVISION_CONFLICT, REVISION_EXHAUSTED }
    public record Revocation(RevokeStatus status,long currentRevision) {
        public Revocation {if(status==null || currentRevision< -1)throw invalid();}
    }
    public record Validity(Instant issuedAt,Instant expiresAt) {
        public Validity {if(issuedAt==null || expiresAt==null || !expiresAt.isAfter(issuedAt))throw invalid();}
    }
    /** Immutable nonsecret reference data. Constructing this record cannot mint evidence or an admission. */
    public record Reference(UUID delegationId,long revision,VirtualExperimentService.CreationReference creation,
            CredentialReference ownerCredential,CredentialReference executorCredential,Instant issuedAt,Instant expiresAt) {
        public Reference {
            if(delegationId==null || revision<0 || creation==null || ownerCredential==null || executorCredential==null
                    || issuedAt==null || expiresAt==null || !expiresAt.isAfter(issuedAt))throw invalid();
        }
        public UUID experimentId(){return creation.experimentId();}
        @Override public String toString(){return "OwnerDelegationReference[REDACTED]";}
    }
    public sealed interface DelegationEvidence permits Evidence {
        Reference reference();
        boolean issuedBy(Object expectedRegistry);
    }
    public static final class Evidence implements DelegationEvidence {
        private final Reference reference;
        private final LocalVirtualOwnerDelegationRegistry issuer;
        private Evidence(Reference reference,LocalVirtualOwnerDelegationRegistry issuer){this.reference=reference;this.issuer=issuer;}
        public Reference reference(){return reference;}
        public boolean issuedBy(Object expectedRegistry){return issuer==expectedRegistry;}
        @Override public String toString(){return "OwnerDelegationEvidence[REDACTED]";}
    }
    /** Private-constructor checked state is consumed only by the context's fresh registry check. */
    public static final class CheckedDelegation {
        private final LocalVirtualAdmissionContext context;
        private final Reference reference;
        private final LocalVirtualPrincipal owner,executor;
        private CheckedDelegation(LocalVirtualAdmissionContext context,Reference reference,LocalVirtualPrincipal owner,LocalVirtualPrincipal executor){
            this.context=context;this.reference=reference;this.owner=owner;this.executor=executor;
        }
        public boolean boundTo(LocalVirtualAdmissionContext expected){return context==expected;}
        public Reference reference(){return reference;}
        public LocalVirtualPrincipal owner(){return owner;}
        public LocalVirtualPrincipal executor(){return executor;}
        @Override public String toString(){return "CheckedOwnerDelegation[REDACTED]";}
    }
    private record Stored(Reference reference,Status status) { }
    private record CreationKey(UUID experimentId,ActionIdentity identity,CredentialReference executor) { }
    private final LocalVirtualAdmissionContext context;
    private final LocalVirtualTokenRegistry credentials;
    private final LocalVirtualCurrentVerifier verifier;
    private final LocalVirtualPrincipalRegistry principals;
    private final VirtualExperimentService creator;
    private final CredentialReference configuredExecutor;
    private final int maximumRecords;
    private final Map<UUID,Stored> records=new LinkedHashMap<>();
    private final Map<CreationKey,UUID> creations=new LinkedHashMap<>();
    public LocalVirtualOwnerDelegationRegistry(LocalVirtualAdmissionContext context,LocalVirtualTokenRegistry credentials,
            LocalVirtualPrincipalRegistry principals,VirtualExperimentService creator,
            CredentialReference configuredExecutor,int maximumRecords){
        this.context=Objects.requireNonNull(context);this.credentials=Objects.requireNonNull(credentials);
        this.creator=Objects.requireNonNull(creator);this.configuredExecutor=Objects.requireNonNull(configuredExecutor);
        this.principals=Objects.requireNonNull(principals);
        this.verifier=new LocalVirtualCurrentVerifier(credentials,this.principals);
        if(maximumRecords<1)throw invalid();this.maximumRecords=maximumRecords;
        if(!context.boundToCurrentGraph(credentials,principals))throw fail(Code.UNAVAILABLE);
    }
    /** Only a live original owner frame and genuine committed creation proof can register a delegation. */
    public synchronized DelegationEvidence mint(Admission owner,VirtualExperimentService.CreationProof proof,
            CredentialEvidence executorEvidence,UUID delegationId,long initialRevision,Validity validity,Instant now){
        if(owner==null || context.current()!=owner)throw fail(Code.UNAUTHENTICATED);
        if(proof==null)throw fail(Code.UNAVAILABLE);
        if(delegationId==null || initialRevision<0 || validity==null || now==null)throw invalid();
        var ownerCredential=owner.credential();var ownerPrincipal=current(ownerCredential,now);
        if(!ownerPrincipal.equals(owner.principal()) || !proof.createdBy(owner))throw fail(Code.FORBIDDEN);
        var creation=proof.reference();requireCreation(creation);
        if(!creation.ownerCredential().equals(ownerCredential) || !creation.creationActorAlias().equals(ownerPrincipal.actorAlias()))throw fail(Code.FORBIDDEN);
        if(!LocalVirtualAccessPolicy.roleAllows(ownerPrincipal,Operation.EXPERIMENT))throw fail(Code.FORBIDDEN);
        var executor=executor(executorEvidence,now);
        if(validity.issuedAt().isAfter(now) || !now.isBefore(validity.expiresAt())
                || validity.issuedAt().isBefore(ownerCredential.issuedAt()) || validity.issuedAt().isBefore(configuredExecutor.issuedAt())
                || validity.expiresAt().isAfter(ownerCredential.expiresAt()) || validity.expiresAt().isAfter(configuredExecutor.expiresAt()))throw fail(Code.UNAUTHENTICATED);
        var key=new CreationKey(creation.experimentId(),creation.creationIdentity(),configuredExecutor);
        if(records.containsKey(delegationId) || creations.containsKey(key))throw fail(Code.CONFLICT);
        if(records.size()>=maximumRecords)throw fail(Code.UNAVAILABLE);
        // Recheck both independent registries and actual committed ownership before publication.
        if(!current(ownerCredential,now).equals(ownerPrincipal) || !executor(executorEvidence,now).equals(executor))throw fail(Code.UNAVAILABLE);
        requireCreation(creation);
        var reference=new Reference(delegationId,initialRevision,creation,ownerCredential,configuredExecutor,validity.issuedAt(),validity.expiresAt());
        records.put(delegationId,new Stored(reference,Status.ACTIVE));creations.put(key,delegationId);
        return new Evidence(reference,this);
    }
    /** Fresh canonical executor possession is mandatory for each exact experiment phase. */
    public LocalVirtualAdmissionContext.DelegatedAdmission openDelegated(CredentialEvidence executorEvidence,
            DelegationEvidence delegation,UUID experimentId,Instant now){
        return context.openDelegated(this,executorEvidence,delegation,experimentId,now);
    }
    synchronized CheckedDelegation checkedFor(LocalVirtualAdmissionContext requestedContext,CredentialEvidence executorEvidence,
            DelegationEvidence delegation,UUID experimentId,Instant now){
        if(requestedContext!=context || !context.boundToCurrentGraph(credentials,principals))throw fail(Code.UNAVAILABLE);
        if(!(delegation instanceof Evidence evidence) || evidence.issuer!=this)throw fail(Code.UNAUTHENTICATED);
        if(experimentId==null || now==null)throw invalid();
        var stored=records.get(evidence.reference.delegationId());
        if(stored==null || stored.status()!=Status.ACTIVE || stored.reference()!=evidence.reference)throw fail(Code.UNAUTHENTICATED);
        var r=stored.reference();
        if(!r.experimentId().equals(experimentId))throw fail(Code.FORBIDDEN);
        if(now.isBefore(r.issuedAt()) || !now.isBefore(r.expiresAt()))throw fail(Code.UNAUTHENTICATED);
        var executor=executor(executorEvidence,now);var owner=current(r.ownerCredential(),now);
        if(!r.executorCredential().equals(configuredExecutor) || !r.creation().ownerCredential().equals(r.ownerCredential())
                || !r.creation().creationActorAlias().equals(owner.actorAlias()) || !LocalVirtualAccessPolicy.roleAllows(owner,Operation.EXPERIMENT))throw fail(Code.FORBIDDEN);
        requireCreation(r.creation());
        if(!current(r.ownerCredential(),now).equals(owner) || !executor(executorEvidence,now).equals(executor))throw fail(Code.UNAVAILABLE);
        requireCreation(r.creation());
        return new CheckedDelegation(context,r,owner,executor);
    }
    public synchronized Revocation revoke(UUID delegationId,long expectedRevision){
        if(delegationId==null || expectedRevision<0)throw invalid();
        var old=records.get(delegationId);
        if(old==null)return new Revocation(RevokeStatus.NOT_FOUND,-1);
        if(old.reference().revision()!=expectedRevision)return new Revocation(RevokeStatus.REVISION_CONFLICT,old.reference().revision());
        if(old.status()==Status.REVOKED)return new Revocation(RevokeStatus.ALREADY_REVOKED,expectedRevision);
        if(expectedRevision==Long.MAX_VALUE)return new Revocation(RevokeStatus.REVISION_EXHAUSTED,expectedRevision);
        var r=old.reference();var next=new Reference(r.delegationId(),expectedRevision+1,r.creation(),r.ownerCredential(),r.executorCredential(),r.issuedAt(),r.expiresAt());
        records.put(delegationId,new Stored(next,Status.REVOKED));return new Revocation(RevokeStatus.REVOKED,next.revision());
    }
    public synchronized int size(){return records.size();}
    private LocalVirtualPrincipal executor(CredentialEvidence evidence,Instant now){
        if(evidence==null || !evidence.issuedBy(credentials))throw fail(Code.UNAUTHENTICATED);
        if(!evidence.reference().equals(configuredExecutor))throw fail(Code.FORBIDDEN);
        return current(configuredExecutor,now);
    }
    private LocalVirtualPrincipal current(CredentialReference reference,Instant now){
        var snapshot=verifier.current(reference,now);
        if(snapshot.state()==CredentialState.UNCONFIRMED)throw fail(Code.UNAVAILABLE);
        if(snapshot.state()!=CredentialState.ACTIVE || snapshot.principal()==null)throw fail(Code.UNAUTHENTICATED);
        return snapshot.principal();
    }
    private void requireCreation(VirtualExperimentService.CreationReference reference){
        if(reference==null || !reference.issuedBy(creator))throw fail(Code.UNAVAILABLE);
        try{creator.requireCurrentCreation(reference);}catch(RuntimeException unknown){throw fail(Code.UNAVAILABLE);}
    }
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("INVALID_OWNER_DELEGATION_INPUT",null);}
    private static Failure fail(Code code){return new Failure(code);}
    @Override public String toString(){return "LocalVirtualOwnerDelegationRegistry[REDACTED]";}
}
