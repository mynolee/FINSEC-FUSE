package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.*;
import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment.Fact;
import com.finsec.fuse.reimplementation.persistence.*;
import java.util.*;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.VirtualGrantFactResolver.*;
import static org.junit.jupiter.api.Assertions.*;

/** Supplied synthetic facts composed through the real reference service; never real trust. */
class VirtualGrantFactResolverTest {
    static final Fact C = Fact.CLEAR;
    static final String HASH = "a".repeat(64), EVIDENCE = "c".repeat(64);
    static UUID id(long n) { return new UUID(12, n); }
    static SyntheticGrantV2Codec.Profile profile() { return new SyntheticGrantV2Codec.Profile(16384, 8192, 8, 64, 1000, 300); }
    static String payload(SyntheticGrantV2Codec.Action a) {
        var m = new LinkedHashMap<String, Object>();
        m.put("actionId", a.actionId().toString()); m.put("workflowId", a.workflowId().toString());
        m.put("generation", a.generation()); m.put("allowedAction", a.allowedAction().name());
        m.put("customerId", a.customerId()); m.put("amountKrw", a.amountKrw());
        m.put("payoutAccountId", a.payoutAccountId().toString()); m.put("targetRunId", a.targetRunId().toString());
        m.put("sourceResultId", a.sourceResultId() == null ? null : a.sourceResultId().toString());
        m.put("evidenceBundleHash", a.evidenceBundleHash()); m.put("approvalId", null); m.put("policyVersion", a.policyVersion());
        return CanonicalJson.sha256(m);
    }
    static List<SyntheticGrantChainStructure.Node> chain(int depth) {
        var list = new ArrayList<SyntheticGrantChainStructure.Node>();
        for (int d = 1; d <= depth; d++) {
            AllowedAction action = d == 1 ? AllowedAction.EVALUATE_KYC : AllowedAction.CREATE_LOAN_RECOMMENDATION;
            var a = new SyntheticGrantV2Codec.Action(id(100+d), id(1), 1, action, "synthetic-customer", 1000L,
                    id(2), id(200+d), d == 1 ? null : id(302), EVIDENCE, null, "synthetic-policy");
            var c = new SyntheticGrantV2Codec.Claims("FUSE-GRANT-v2", "HMAC-SHA256", "synthetic-key", id(400+d),
                    id(1), 1, id(4), "synthetic-principal", "synthetic-intent", "synthetic-issuer", "synthetic-source",
                    "synthetic-target", d == 1 ? null : id(200+d-1), a.targetRunId(), action, a.customerId(), a.amountKrw(),
                    a.payoutAccountId(), a.sourceResultId(), EVIDENCE, d == 1 ? null : id(400+d-1), d, a.actionId(),
                    payload(a), a.policyVersion(), id(5), null, 100, 400);
            list.add(new SyntheticGrantChainStructure.Node(c,a));
        }
        return list;
    }
    static SyntheticGrantIssuerBindings.Binding binding(int depth) {
        return new SyntheticGrantIssuerBindings.Binding("synthetic-subject", id(7), "synthetic-principal", "synthetic-issuer",
                depth == 1 ? SyntheticGrantIssuerBindings.Stage.KYC_EVALUATOR : SyntheticGrantIssuerBindings.Stage.LOAN_RECOMMENDER,
                depth == 1 ? AllowedAction.EVALUATE_KYC : AllowedAction.CREATE_LOAN_RECOMMENDATION,
                "synthetic-customer", id(4), id(1), "synthetic-intent",
                new SyntheticGrantIssuerBindings.KeyReference("synthetic-key", "HMAC-SHA256", "synthetic-owner-reference"));
    }
    static SyntheticGrantReplayAssessment.CurrentReadFacts reads(Fact ancestor) {
        return new SyntheticGrantReplayAssessment.CurrentReadFacts(C,C,C,C,C,ancestor,C);
    }
    static SyntheticGrantTemporalAssessment.RevocationFacts revocations() {
        return new SyntheticGrantTemporalAssessment.RevocationFacts(C,C,C,C,C,C,C,C,C);
    }
    static KeyFacts key(SyntheticGrantKeyLifecycleAssessment.Lifecycle lifecycle,
                        SyntheticGrantKeyLifecycleAssessment.Ordering ordering,
                        SyntheticGrantKeyLifecycleAssessment.MaterialFact material) {
        var k = new SyntheticGrantKeyLifecycleAssessment.KeyBinding("synthetic-key", "synthetic-issuer", "HMAC-SHA256", "synthetic-key-version");
        return new KeyFacts(k, new SyntheticGrantKeyLifecycleAssessment.KeySnapshot(k,lifecycle), ordering, material, C,
                new SyntheticGrantKeyLifecycleAssessment.CurrentUseFacts(C,C,C,C,C,C));
    }
    static final class CountingStore implements TransactionalStore {
        final VirtualTransactionalStore delegate = new VirtualTransactionalStore(); int journalReads;
        public String mode() { return delegate.mode(); }
        public Map<String,Map<String,Map<String,Object>>> snapshot() { return delegate.snapshot(); }
        public <R> R transaction(Function<Tx,R> work) {
            return delegate.transaction(tx -> work.apply(new Tx() {
                public Map<String,Object> get(String table,String key) {
                    if (table.equals(ActionJournal.TABLE)) journalReads++; return tx.get(table,key);
                }
                public Map<String,Map<String,Object>> rows(String table) { return tx.rows(table); }
                public void put(String table,String key,Map<String,Object> value) { tx.put(table,key,value); }
            }));
        }
    }
    static final class Local implements LocalFacts {
        Snapshot snapshot; OwnedTx first; int loads, versions, driftAt = Integer.MAX_VALUE;
        void begin() { first = null; loads = 0; versions = 0; }
        void same(OwnedTx tx) { if (first == null) first = tx; else assertSame(first,tx); }
        public Snapshot load(ServerContext context, StageCommand command, OwnedTx tx) {
            same(tx); loads++; return snapshot;
        }
        public Fact versionChanged(ServerContext context, StageCommand command, OwnedTx tx, String expected) {
            same(tx); assertEquals(snapshot.version(),expected);
            return ++versions >= driftAt ? Fact.UNKNOWN : C;
        }
    }
    static final class Fixture {
        final CountingStore store = new CountingStore();
        final VirtualGrantTransactionJournal journal = VirtualGrantTransactionJournal.detachedReference(store, () -> id(800), 65536);
        final Local local = new Local();
        final SyntheticGrantIssuerBindings.Prepared registry = SyntheticGrantIssuerBindings.prepare(
                "synthetic-registry-version", List.of(binding(1),binding(2)), new SyntheticGrantIssuerBindings.Limits(8,128));
        final VirtualGrantFactResolver resolver = new VirtualGrantFactResolver(registry,local);
        final GrantStageTransactionService service = new GrantStageTransactionService(journal,resolver);
        final ServerContext context = () -> "synthetic-actor";
        final GrantSnapshot root = grant(1);
        final StageCommand rootCommand = command(1,500);
        final OutsidePreparedResult rootResult = result(600);
        Fixture() { journal.seedSyntheticRoot(root); local.snapshot = snapshot(1); }
        GrantSnapshot grant(int depth) {
            var c = chain(depth).get(depth-1).claims();
            return new GrantSnapshot(c.grantId(),c.actionId(),c.targetRunId(),c.workflowId(),c.generation(),c.customerId(),c.allowedAction(),GrantState.ISSUED);
        }
        StageCommand command(int depth,long request) {
            var g = grant(depth);
            return new StageCommand(new CommandIdentity("synthetic-actor",id(request),"synthetic-stage","command-version-1",HASH,
                    g.grantId(),g.actionId(),g.targetRunId(),g.workflowId(),g.generation(),g.customerId()),g.action());
        }
        OutsidePreparedResult result(long n) {
            return new OutsidePreparedResult(id(n),SyntheticGrantStageBinding.BusinessConclusion.POSITIVE,
                    "AGENT_RESULT_BINDING_RECORD_1",new byte[] {1,2},new byte[] {3,4});
        }
        Snapshot snapshot(int depth) {
            var nodes = chain(depth); var c = nodes.get(depth-1).claims();
            var scope = new SyntheticGrantStageBinding.Scope(c.workflowId(),c.generation(),c.customerId());
            var body = new SyntheticGrantStageBinding.BodyBinding("synthetic-body-version",new byte[]{'{','}'},HASH,"b".repeat(64),EVIDENCE,
                    c.sourceRunId(),c.sourceResultId(),"synthetic-validation-reference");
            var run = new SyntheticGrantStageBinding.RunSnapshot(c.targetRunId(),c.actionId(),scope,
                    depth == 1 ? SyntheticGrantStageBinding.AgentRole.KYC : SyntheticGrantStageBinding.AgentRole.LOAN,
                    SyntheticGrantStageBinding.RunStatus.VALIDATED);
            var output = new SyntheticGrantStageBinding.ResultSnapshot(id(600+depth-1),c.targetRunId(),c.workflowId(),c.generation(),
                    SyntheticGrantStageBinding.ResultStatus.VALIDATED,SyntheticGrantStageBinding.BusinessConclusion.POSITIVE,body);
            var agent = new AgentFacts(profile(),nodes,new SyntheticGrantStageBinding.BindingProfile(2),run,output,
                    new SyntheticGrantStageBinding.WorkflowSnapshot(scope),new SyntheticGrantStageBinding.ExpectedResultBinding(output.resultId(),body),
                    new ResolvedStage(grant(depth),result(600+depth-1),run.status(),output.status(),List.of()));
            return new Snapshot("synthetic-snapshot-version",new Descriptor("synthetic-actor",binding(depth),"synthetic-owner-reference","synthetic-key-version"),
                    reads(C),new SyntheticGrantTemporalAssessment.TemporalFacts(150,100,400,
                    depth == 1 ? SyntheticGrantTemporalAssessment.ChainPosition.ROOT : SyntheticGrantTemporalAssessment.ChainPosition.CHILD,
                    depth == 1 ? null : 400L),revocations(),key(SyntheticGrantKeyLifecycleAssessment.Lifecycle.ACTIVE,
                    SyntheticGrantKeyLifecycleAssessment.Ordering.BEFORE_RETIREMENT,SyntheticGrantKeyLifecycleAssessment.MaterialFact.AVAILABLE),agent,null);
        }
        void replace(Descriptor d, SyntheticGrantReplayAssessment.CurrentReadFacts r,
                     SyntheticGrantTemporalAssessment.TemporalFacts time, KeyFacts k, AgentFacts agent, IssuanceFacts issuance) {
            Snapshot s=local.snapshot; local.snapshot=new Snapshot(s.version(),d,r,time,s.revocation(),k,agent,issuance);
        }
        StageOutcome complete() { local.begin(); return service.completeStage(context,rootCommand,rootResult); }
        StageOutcome reconcile() { local.begin(); return service.reconcile(context,rootCommand); }
    }

    @Test void actualResolverCompletesThenReplaysWithoutReloadingNewWorkOrAutoChild() {
        Fixture f=new Fixture(); StageOutcome first=f.complete();
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,first.status()); assertTrue(f.local.loads>=2);
        assertEquals(1,f.store.snapshot().get("virtual_grant_profile_grants").size());
        var before=f.store.snapshot(); StageOutcome replay=f.reconcile();
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,replay.status()); assertEquals(first.receipt(),replay.receipt());
        assertEquals(1,f.local.loads); assertEquals(before,f.store.snapshot());
        assertFalse(first.actualAuthority()); assertFalse(first.durable());
        assertFalse(f.resolver.actualAuthorizationEstablished()); assertFalse(f.resolver.actualRegistryProvenanceEstablished());
        assertFalse(f.resolver.executionAuthorityGranted());
    }

    @Test void commonAliasDenialAndMissingOrMismatchedKeyJoinPrecedeAnyJournalLookup() {
        for(int mode=0;mode<6;mode++) {
            Fixture f=new Fixture(); Snapshot s=f.local.snapshot; Descriptor d=s.descriptor(); KeyFacts k=s.key();
            if(mode==0) d=new Descriptor("other-alias",d.issuerBinding(),d.keyOwnerReference(),d.keyVersion());
            if(mode==1) d=new Descriptor(d.actorAlias(),d.issuerBinding(),"other-owner",d.keyVersion());
            if(mode==2) d=new Descriptor(d.actorAlias(),d.issuerBinding(),d.keyOwnerReference(),"other-version");
            if(mode==3) k=null;
            if(mode==4) {
                var b=d.issuerBinding();
                var absent=new SyntheticGrantIssuerBindings.Binding("unregistered-subject",b.actorId(),b.principalId(),b.issuerId(),
                        b.stage(),b.action(),b.customerId(),b.rootAuthorizationId(),b.workflowId(),b.intent(),b.keyReference());
                d=new Descriptor(d.actorAlias(),absent,d.keyOwnerReference(),d.keyVersion());
            }
            if(mode==5) {
                var other=new SyntheticGrantKeyLifecycleAssessment.KeyBinding("other-kid",k.expected().issuer(),k.expected().algorithm(),k.expected().keyVersion());
                k=new KeyFacts(other,new SyntheticGrantKeyLifecycleAssessment.KeySnapshot(other,
                        SyntheticGrantKeyLifecycleAssessment.Lifecycle.ACTIVE),k.ordering(),k.material(),k.issuanceBindingChanged(),k.currentUse());
            }
            f.replace(d,s.currentRead(),s.temporal(),k,s.agent(),null); f.store.journalReads=0;
            StageOutcome result=f.complete();
            assertEquals(mode==0?Status.REFUSED_BEFORE_ADMISSION:Status.UNCONFIRMED_BEFORE_ADMISSION,result.status());
            assertNull(result.receipt()); assertEquals(0,f.store.journalReads);
        }
    }

    @Test void currentAncestorDenialHidesEvenExistingReferenceReceiptBeforeLookup() {
        Fixture f=new Fixture(); f.complete(); var before=f.store.snapshot(); Snapshot s=f.local.snapshot;
        f.replace(s.descriptor(),reads(Fact.ACTIVE),s.temporal(),s.key(),s.agent(),null); f.store.journalReads=0;
        assertEquals(Status.REFUSED_BEFORE_ADMISSION,f.reconcile().status());
        assertEquals(0,f.store.journalReads); assertEquals(before,f.store.snapshot());
    }

    @Test void versionUnknownBeforeLookupAndDriftBeforeCommitNeverConsume() {
        for(int drift:List.of(1,3)) {
            Fixture f=new Fixture(); f.local.driftAt=drift; var before=f.store.snapshot(); f.store.journalReads=0;
            assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,f.complete().status());
            if(drift==1) assertEquals(0,f.store.journalReads);
            assertEquals(before,f.store.snapshot());
        }
    }

    @Test void onlyOwnExpiredHistoryMayReplayWithoutOutstandingMaterial() {
        Fixture f=new Fixture(); f.complete(); var before=f.store.snapshot(); Snapshot s=f.local.snapshot;
        f.replace(s.descriptor(),s.currentRead(),new SyntheticGrantTemporalAssessment.TemporalFacts(400,100,400,
                SyntheticGrantTemporalAssessment.ChainPosition.ROOT,null),
                key(SyntheticGrantKeyLifecycleAssessment.Lifecycle.RETIRED,SyntheticGrantKeyLifecycleAssessment.Ordering.UNKNOWN,
                        SyntheticGrantKeyLifecycleAssessment.MaterialFact.UNKNOWN),null,null);
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,f.reconcile().status()); assertEquals(before,f.store.snapshot());
        Snapshot expired=f.local.snapshot;
        f.replace(expired.descriptor(),reads(Fact.ACTIVE),expired.temporal(),expired.key(),null,null);
        assertEquals(Status.REFUSED_BEFORE_ADMISSION,f.reconcile().status()); assertEquals(before,f.store.snapshot());
    }

    @Test void retiredOutstandingRequiresBeforeOrderingAndAvailableMaterial() {
        for(var order:List.of(SyntheticGrantKeyLifecycleAssessment.Ordering.AT_RETIREMENT,
                SyntheticGrantKeyLifecycleAssessment.Ordering.UNKNOWN)) {
            Fixture f=new Fixture(); Snapshot s=f.local.snapshot;
            f.replace(s.descriptor(),s.currentRead(),s.temporal(),key(SyntheticGrantKeyLifecycleAssessment.Lifecycle.RETIRED,
                    order,SyntheticGrantKeyLifecycleAssessment.MaterialFact.AVAILABLE),s.agent(),null);
            var before=f.store.snapshot(); assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,f.complete().status());
            assertEquals(before,f.store.snapshot());
        }
        Fixture allowed=new Fixture(); Snapshot s=allowed.local.snapshot;
        allowed.replace(s.descriptor(),s.currentRead(),s.temporal(),key(SyntheticGrantKeyLifecycleAssessment.Lifecycle.RETIRED,
                SyntheticGrantKeyLifecycleAssessment.Ordering.BEFORE_RETIREMENT,SyntheticGrantKeyLifecycleAssessment.MaterialFact.AVAILABLE),s.agent(),null);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,allowed.complete().status());
    }

    @Test void actualGrantAndOutsidePreparedMustEqualResolvedStage() {
        for(boolean grantMismatch:List.of(false,true)) {
            Fixture f=new Fixture(); Snapshot s=f.local.snapshot; AgentFacts a=s.agent();
            var wrongGrant=new GrantSnapshot(id(999),f.root.actionId(),f.root.targetRunId(),f.root.workflowId(),1,
                    f.root.customerId(),f.root.action(),GrantState.ISSUED);
            var wrong=new ResolvedStage(grantMismatch?wrongGrant:f.root,grantMismatch?f.rootResult:f.result(999),
                    a.resolved().runStatus(),a.resolved().resultStatus(),List.of());
            AgentFacts changed=new AgentFacts(a.codecProfile(),a.nodes(),a.bindingProfile(),a.run(),a.result(),a.workflow(),a.expectedResult(),wrong);
            f.replace(s.descriptor(),s.currentRead(),s.temporal(),s.key(),changed,null); var before=f.store.snapshot();
            assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,f.complete().status()); assertEquals(before,f.store.snapshot());
        }
    }

    @Test void successorUsesSeparateSnapshotAndRetiredKeyCannotIssueNewChild() {
        for(boolean retired:List.of(false,true)) {
            Fixture f=new Fixture(); f.complete(); GrantSnapshot child=f.grant(2); Snapshot s=f.snapshot(2);
            KeyFacts k=retired?key(SyntheticGrantKeyLifecycleAssessment.Lifecycle.RETIRED,
                    SyntheticGrantKeyLifecycleAssessment.Ordering.BEFORE_RETIREMENT,SyntheticGrantKeyLifecycleAssessment.MaterialFact.AVAILABLE):s.key();
            f.local.snapshot=new Snapshot(s.version(),s.descriptor(),s.currentRead(),s.temporal(),s.revocation(),k,null,
                    new IssuanceFacts(f.root.grantId(),child,profile(),chain(2)));
            var before=f.store.snapshot(); f.local.begin();
            StageOutcome issued=f.service.issueSuccessor(f.context,f.command(2,501),f.root.grantId(),child);
            assertEquals(retired?Status.UNCONFIRMED_BEFORE_ADMISSION:Status.VIRTUAL_COMMITTED_IN_PROCESS,issued.status());
            if(retired) assertEquals(before,f.store.snapshot());
            else { assertEquals(ReceiptKind.ISSUANCE,issued.receipt().kind());
                assertEquals(2,f.store.snapshot().get("virtual_grant_profile_grants").size()); }
        }
    }
    @Test void ownExpiredConsumedLoanCannotBypassAnActuallyExpiredParent() {
        Fixture f=new Fixture(); f.complete(); GrantSnapshot child=f.grant(2); Snapshot loan=f.snapshot(2);
        f.local.snapshot=new Snapshot(loan.version(),loan.descriptor(),loan.currentRead(),loan.temporal(),loan.revocation(),loan.key(),null,
                new IssuanceFacts(f.root.grantId(),child,profile(),chain(2)));
        f.local.begin();
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,
                f.service.issueSuccessor(f.context,f.command(2,501),f.root.grantId(),child).status());
        f.local.snapshot=loan; f.local.begin(); StageCommand complete=f.command(2,502);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,
                f.service.completeStage(f.context,complete,f.result(601)).status());
        var before=f.store.snapshot();
        f.local.snapshot=new Snapshot(loan.version(),loan.descriptor(),reads(C),
                new SyntheticGrantTemporalAssessment.TemporalFacts(400,100,400,
                        SyntheticGrantTemporalAssessment.ChainPosition.CHILD,400L),
                loan.revocation(),loan.key(),null,null);
        f.local.begin(); StageOutcome denied=f.service.reconcile(f.context,complete);
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,denied.status());
        assertNull(denied.receipt()); assertEquals(before,f.store.snapshot());
    }

    @Test void actualRootChainCannotBeRelabelledAsChildWithASuppliedParent() {
        Fixture f=new Fixture();Snapshot root=f.local.snapshot;
        f.replace(root.descriptor(),root.currentRead(),new SyntheticGrantTemporalAssessment.TemporalFacts(150,100,400,
                SyntheticGrantTemporalAssessment.ChainPosition.CHILD,400L),root.key(),root.agent(),null);
        var before=f.store.snapshot();StageOutcome result=f.complete();
        assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,result.status());assertNull(result.receipt());
        assertEquals(before,f.store.snapshot());
    }

    static SyntheticGrantChainStructure.Node retimed(SyntheticGrantChainStructure.Node node,long expiry) {
        var c=node.claims();
        var changed=new SyntheticGrantV2Codec.Claims(c.format(),c.algorithm(),c.kid(),c.grantId(),c.workflowId(),c.generation(),
                c.rootAuthorizationId(),c.principalId(),c.originIntent(),c.issuer(),c.sourceAgent(),c.targetAgent(),c.sourceRunId(),
                c.targetRunId(),c.allowedAction(),c.customerId(),c.amountKrw(),c.payoutAccountId(),c.sourceResultId(),
                c.evidenceBundleHash(),c.parentGrantId(),c.depth(),c.actionId(),c.payloadHash(),c.policyVersion(),
                c.riskLedgerId(),c.approvalId(),c.issuedAt(),expiry);
        return new SyntheticGrantChainStructure.Node(changed,node.action());
    }

    @Test void actualLoanParentExpiryAndChildKindCannotBeOverriddenByTemporalSnapshot() {
        for(int mode=0;mode<3;mode++) {
            Fixture f=new Fixture();f.complete();GrantSnapshot child=f.grant(2);Snapshot loan=f.snapshot(2);
            f.local.snapshot=new Snapshot(loan.version(),loan.descriptor(),loan.currentRead(),loan.temporal(),loan.revocation(),loan.key(),null,
                    new IssuanceFacts(f.root.grantId(),child,profile(),chain(2)));
            f.local.begin();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,
                    f.service.issueSuccessor(f.context,f.command(2,501),f.root.grantId(),child).status());
            var nodes=new ArrayList<>(loan.agent().nodes());
            nodes.set(0,retimed(nodes.get(0),mode==0?200:400));nodes.set(1,retimed(nodes.get(1),300));
            AgentFacts old=loan.agent();
            var agent=new AgentFacts(old.codecProfile(),nodes,old.bindingProfile(),old.run(),old.result(),old.workflow(),old.expectedResult(),old.resolved());
            f.local.snapshot=new Snapshot(loan.version(),loan.descriptor(),loan.currentRead(),
                    new SyntheticGrantTemporalAssessment.TemporalFacts(150,100,300,
                            mode==1?SyntheticGrantTemporalAssessment.ChainPosition.ROOT:SyntheticGrantTemporalAssessment.ChainPosition.CHILD,
                            mode==1?null:400L),loan.revocation(),loan.key(),agent,null);
            var before=f.store.snapshot();f.local.begin();
            StageOutcome result=f.service.completeStage(f.context,f.command(2,502),f.result(601));
            assertEquals(mode==2?Status.VIRTUAL_COMMITTED_IN_PROCESS:Status.UNCONFIRMED_BEFORE_ADMISSION,result.status());
            if(mode!=2){assertNull(result.receipt());assertEquals(before,f.store.snapshot());}
        }
    }

}
