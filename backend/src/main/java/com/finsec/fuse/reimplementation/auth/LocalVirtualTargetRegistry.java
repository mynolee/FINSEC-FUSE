package com.finsec.fuse.reimplementation.auth;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.simulation.SimulationAccess.Operation;
import com.finsec.fuse.reimplementation.simulation.SimulationFailure;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

/** Explicit typed assignments and finite owned collection admission; never an ordinary null-scope grant. */
public final class LocalVirtualTargetRegistry {
    public sealed interface Target permits Workflow,Customer,Experiment,FixtureSet,Source,Agent,Artifact,ExperimentCreation { }
    public record Workflow(UUID workflowId,String customerId) implements Target {public Workflow{required(workflowId);synthetic(customerId);}}
    public record Customer(String customerId) implements Target {public Customer{synthetic(customerId);}}
    public record Experiment(UUID experimentId) implements Target {public Experiment{required(experimentId);}}
    public record FixtureSet(String fixtureSetId) implements Target {public FixtureSet{synthetic(fixtureSetId);}}
    public record Source(UUID documentId,int documentVersion) implements Target {public Source{required(documentId);positive(documentVersion);}}
    public record Agent(String agentId,int agentVersion) implements Target {public Agent{synthetic(agentId);positive(agentVersion);}}
    public enum ArtifactKind { RUN,RESULT }
    public record Artifact(UUID artifactId,ArtifactKind kind) implements Target {public Artifact{required(artifactId);required(kind);}}
    public record ExperimentCreation(UUID creatorPrincipalId,String fixtureSetId) implements Target {public ExperimentCreation{required(creatorPrincipalId);synthetic(fixtureSetId);}}
    public record Intent(Operation operation,Target boundary){public Intent{required(operation);required(boundary);}}
    public record Assignment(UUID principalId,long bindingRevision,Operation operation,Target target){
        public Assignment{required(principalId);revision(bindingRevision);required(operation);required(target);}
    }
    public record Declaration(UUID principalId,long bindingRevision,Intent intent){
        public Declaration{required(principalId);revision(bindingRevision);required(intent);}
    }
    public record Limits(int maximumAssignments,int maximumDeclarations,int maximumMembers,int maximumRelations,int maximumCases,int maximumSnapshotBytes){
        public Limits{positive(maximumAssignments);positive(maximumDeclarations);positive(maximumMembers);positive(maximumRelations);positive(maximumCases);positive(maximumSnapshotBytes);}
    }
    /** Mandatory trusted actual-domain adapter; a supplied list/boolean/hash alone is not completeness proof. */
    @FunctionalInterface public interface OwnedResolver {
        OwnedCollection open(Intent intent,LocalVirtualPrincipal currentPrincipal,Limits limits);
    }
    /** One owned stable read scope; must verify full target set, domain relationships and changes/new members. */
    public interface OwnedCollection extends AutoCloseable {
        void requireCompleteCurrent();
        List<Target> members();
        int relationCount();
        int caseCount();
        @Override void close();
    }
    /** Only this registry can construct the checked, finite snapshot. It is metadata, not bearer evidence. */
    public static final class CompleteSnapshot {
        private final Intent intent;private final List<Target> members;private final long assignmentRevision;
        private CompleteSnapshot(Intent intent,List<Target> members,long revision){this.intent=intent;this.members=members;this.assignmentRevision=revision;}
        public Intent intent(){return intent;}public List<Target> members(){return members;}public long assignmentRevision(){return assignmentRevision;}
        @Override public String toString(){return "CompleteTypedTargetSnapshot[REDACTED]";}
    }
    public enum Update { APPLIED,CONFLICT }
    private record State(long revision,Set<Assignment> assignments,Set<Declaration> declarations){ }
    private final LocalVirtualTokenRegistry tokens;
    private final LocalVirtualPrincipalRegistry principals;
    private final LocalVirtualAdmissionContext context;
    private final LocalVirtualCurrentVerifier verifier;
    private final Limits limits;private final OwnedResolver resolver;
    private final ThreadLocal<CollectionAdmission> local=new ThreadLocal<>();
    private State state=new State(0,Set.of(),Set.of());
    public LocalVirtualTargetRegistry(LocalVirtualTokenRegistry tokens,LocalVirtualPrincipalRegistry principals,
            LocalVirtualAdmissionContext context,Limits limits,OwnedResolver resolver){
        if(tokens==null||principals==null||context==null||limits==null)throw SimulationFailure.invalid();
        if(!context.boundToCredentialIssuer(tokens))throw SimulationFailure.unavailable();
        this.tokens=tokens;this.principals=principals;this.context=context;this.limits=limits;this.resolver=resolver;
        verifier=new LocalVirtualCurrentVerifier(tokens,principals);
    }
    /** Low-level prepared data installation, not an administrative authorization endpoint. No default assignments. */
    public synchronized Update replacePrepared(long expectedRevision,List<Assignment> assignments,List<Declaration> declarations){
        revision(expectedRevision);if(assignments==null||declarations==null)throw SimulationFailure.invalid();
        final List<Assignment> a;final List<Declaration> d;
        try{a=List.copyOf(assignments);d=List.copyOf(declarations);}catch(RuntimeException invalid){throw SimulationFailure.invalid();}
        if(a.size()>limits.maximumAssignments()||d.size()>limits.maximumDeclarations())throw SimulationFailure.invalid();
        var as=new HashSet<>(a);var ds=new HashSet<>(d);
        if(as.size()!=a.size()||ds.size()!=d.size())throw SimulationFailure.invalid();
        if(state.revision()!=expectedRevision)return Update.CONFLICT;
        final long next;try{next=Math.addExact(expectedRevision,1);}catch(ArithmeticException invalid){throw SimulationFailure.unavailable();}
        state=new State(next,Set.copyOf(as),Set.copyOf(ds));return Update.APPLIED;
    }
    public synchronized long revision(){return state.revision();}
    private synchronized State captured(){return state;}
    public CollectionAdmission currentCollection(){return local.get();}
    public CollectionAdmission openCollection(LocalVirtualAdmissionContext.Admission owner,
            LocalVirtualAdmissionContext.CredentialEvidence evidence,Intent intent,Instant now){
        if(owner==null||evidence==null||now==null||!evidence.issuedBy(tokens))throw SimulationFailure.unauthenticated();
        required(intent);if(local.get()!=null||context.current()!=owner)throw SimulationFailure.unavailable();
        if(!owner.credential().equals(evidence.reference()))throw SimulationFailure.unauthenticated();
        var current=verifier.current(evidence.reference(),now);
        if(current.state()==LocalVirtualAdmissionContext.CredentialState.UNCONFIRMED)throw SimulationFailure.unavailable();
        if(current.state()!=LocalVirtualAdmissionContext.CredentialState.ACTIVE)throw SimulationFailure.unauthenticated();
        var principal=current.principal();
        if(principal==null||principal!=owner.principal())throw SimulationFailure.unavailable();
        if(!LocalVirtualAccessPolicy.roleAllows(principal,intent.operation()))throw SimulationFailure.forbidden();
        // Preserve the ordinary first-operation/first-resource latch. UNKNOWN is not the C grant.
        if(owner.authorize(intent.operation(),null,null)==LocalVirtualAccessPolicy.Decision.FORBIDDEN)
            throw SimulationFailure.forbidden();
        if(intent.boundary() instanceof ExperimentCreation creation&&!creation.creatorPrincipalId().equals(principal.principalId()))
            throw SimulationFailure.forbidden();
        var selected=captured();
        if(!selected.declarations().contains(new Declaration(principal.principalId(),principal.bindingRevision(),intent))||resolver==null)
            throw SimulationFailure.unavailable();
        requireAssigned(selected,principal,intent.operation(),intent.boundary());
        OwnedCollection owned=null;
        try{
            owned=resolver.open(intent,principal,limits);if(owned==null)throw SimulationFailure.unavailable();
            owned.requireCompleteCurrent();
            var members=List.copyOf(owned.members());
            if(members.size()>limits.maximumMembers()||new HashSet<>(members).size()!=members.size())throw SimulationFailure.unavailable();
            int relations=owned.relationCount();if(relations<0||relations>limits.maximumRelations())throw SimulationFailure.unavailable();
            int cases=owned.caseCount();if(cases<0||cases>limits.maximumCases())throw SimulationFailure.unavailable();
            long bytes=Math.addExact(intent.boundary().toString().getBytes(StandardCharsets.UTF_8).length,
                    intent.operation().name().getBytes(StandardCharsets.UTF_8).length);
            if(bytes>limits.maximumSnapshotBytes())throw SimulationFailure.unavailable();
            for(var member:members){
                requireAssigned(selected,principal,intent.operation(),member);
                bytes=Math.addExact(bytes,member.toString().getBytes(StandardCharsets.UTF_8).length);
                if(bytes>limits.maximumSnapshotBytes())throw SimulationFailure.unavailable();
            }
            owned.requireCompleteCurrent();
            var after=verifier.current(evidence.reference(),now);
            if(captured()!=selected||after.state()!=LocalVirtualAdmissionContext.CredentialState.ACTIVE||after.principal()!=principal)
                throw SimulationFailure.unavailable();
            var admission=new CollectionAdmission(owner,evidence.reference(),principal,selected,owned,
                    new CompleteSnapshot(intent,members,selected.revision()),Thread.currentThread());
            local.set(admission);owned=null;return admission;
        }catch(SimulationFailure fixed){throw fixed;}
        catch(RuntimeException unavailable){throw SimulationFailure.unavailable();}
        finally{if(owned!=null)try{owned.close();}catch(RuntimeException uncertain){throw SimulationFailure.unavailable();}}
    }
    private static void requireAssigned(State selected,LocalVirtualPrincipal principal,Operation op,Target target){
        if(!selected.assignments().contains(new Assignment(principal.principalId(),principal.bindingRevision(),op,target)))
            throw SimulationFailure.unavailable();
    }
    public final class CollectionAdmission implements AutoCloseable {
        private final LocalVirtualAdmissionContext.Admission owner;
        private final LocalVirtualAdmissionContext.CredentialReference credential;
        private final LocalVirtualPrincipal principal;private final State selected;private final OwnedCollection owned;
        private final CompleteSnapshot snapshot;private final Thread thread;private boolean closed;
        private CollectionAdmission(LocalVirtualAdmissionContext.Admission owner,LocalVirtualAdmissionContext.CredentialReference credential,
                LocalVirtualPrincipal principal,State selected,OwnedCollection owned,CompleteSnapshot snapshot,Thread thread){
            this.owner=owner;this.credential=credential;this.principal=principal;this.selected=selected;this.owned=owned;this.snapshot=snapshot;this.thread=thread;
        }
        private void live(){if(Thread.currentThread()!=thread||closed||local.get()!=this||context.current()!=owner)throw SimulationFailure.unavailable();owner.principal();}
        /** Bind a service's configured context to this exact live parent, never an alias-only comparison. */
        public void requireOwner(LocalVirtualAdmissionContext expectedContext){
            live();
            if(LocalVirtualTargetRegistry.this.context!=expectedContext||expectedContext.current()!=owner)
                throw SimulationFailure.unavailable();
        }
        /** Exact service-owned native frame join, without exposing the captured parent. */
        public void requireOwner(LocalVirtualAdmissionContext.Admission expected){
            live();if(owner!=expected)throw SimulationFailure.unavailable();
        }
        public CompleteSnapshot snapshot(){live();return snapshot;}
        /** Explicit current time at each boundary, no implicit clock/TTL/in-flight cancellation guarantee. */
        public void requireCurrent(Instant now){
            live();if(now==null)throw SimulationFailure.invalid();
            var current=verifier.current(credential,now);
            if(current.state()==LocalVirtualAdmissionContext.CredentialState.UNCONFIRMED)throw SimulationFailure.unavailable();
            if(current.state()!=LocalVirtualAdmissionContext.CredentialState.ACTIVE)throw SimulationFailure.unauthenticated();
            if(current.principal()!=principal||captured()!=selected)throw SimulationFailure.unavailable();
            owned.requireCompleteCurrent();
            var after=verifier.current(credential,now);
            if(after.state()!=LocalVirtualAdmissionContext.CredentialState.ACTIVE||after.principal()!=principal||captured()!=selected)
                throw SimulationFailure.unavailable();
        }
        public void requireMember(ActorRef actor,Operation operation,Target target,Instant now){
            requireCurrent(now);if(actor==null||!principal.actorAlias().equals(actor.actorId())||operation!=snapshot.intent.operation())throw SimulationFailure.forbidden();
            if(!snapshot.intent.boundary().equals(target)&&!snapshot.members.contains(target))throw SimulationFailure.forbidden();
        }
        public void requireCreation(ActorRef actor,String fixtureSetId,Instant now){
            live();var target=new ExperimentCreation(principal.principalId(),fixtureSetId);
            if(snapshot.intent.operation()!=Operation.EXPERIMENT||!snapshot.intent.boundary().equals(target))
                throw SimulationFailure.forbidden();
            requireMember(actor,Operation.EXPERIMENT,target,now);
        }
        @Override public void close(){
            if(Thread.currentThread()!=thread)throw SimulationFailure.unavailable();if(closed)return;
            if(local.get()!=this)throw SimulationFailure.unavailable();
            try{owned.requireCompleteCurrent();if(captured()!=selected)throw SimulationFailure.unavailable();}
            finally{closed=true;local.remove();try{owned.close();}catch(RuntimeException unavailable){throw SimulationFailure.unavailable();}}
        }
        @Override public String toString(){return "TypedCollectionAdmission[REDACTED]";}
    }
    private static void required(Object value){if(value==null)throw SimulationFailure.invalid();}
    private static void positive(int value){if(value<1)throw SimulationFailure.invalid();}
    private static void revision(long value){if(value<0)throw SimulationFailure.invalid();}
    private static void synthetic(String value){try{SimulationSpec.synthetic(value);}catch(RuntimeException invalid){throw SimulationFailure.invalid();}}
    @Override public String toString(){return "LocalVirtualTargetRegistry[REDACTED]";}
}
