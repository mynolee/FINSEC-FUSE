package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.*;
import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment.Fact;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import java.util.*;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.VirtualGrantFactResolver.*;
import static com.finsec.fuse.reimplementation.grant.VirtualMockPaymentFactResolver.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentTransactionBinding.*;
import static org.junit.jupiter.api.Assertions.*;

/** Actual reference composition with explicit synthetic local facts, never actual authority. */
class VirtualMockPaymentFactResolverTest {
    static UUID id(long n) { return VirtualGrantFactResolverTest.id(n); }
    static List<SyntheticGrantChainStructure.Node> paymentChain(long amount) {
        var nodes=new ArrayList<>(VirtualGrantFactResolverTest.chain(2));
        var a=new SyntheticGrantV2Codec.Action(id(103),id(1),1,AllowedAction.EXECUTE_MOCK_PAYMENT,"synthetic-customer",amount,
                id(2),id(203),id(303),VirtualGrantFactResolverTest.EVIDENCE,id(3),"synthetic-policy");
        String payload=CanonicalJson.sha256(Map.ofEntries(Map.entry("actionId",a.actionId().toString()),
                Map.entry("workflowId",a.workflowId().toString()),Map.entry("generation",1),Map.entry("allowedAction",a.allowedAction().name()),
                Map.entry("customerId",a.customerId()),Map.entry("amountKrw",a.amountKrw()),Map.entry("payoutAccountId",a.payoutAccountId().toString()),
                Map.entry("targetRunId",a.targetRunId().toString()),Map.entry("sourceResultId",a.sourceResultId().toString()),
                Map.entry("evidenceBundleHash",a.evidenceBundleHash()),Map.entry("approvalId",a.approvalId().toString()),Map.entry("policyVersion",a.policyVersion())));
        var claims=new SyntheticGrantV2Codec.Claims("FUSE-GRANT-v2","HMAC-SHA256","synthetic-key",id(403),id(1),1,id(4),
                "synthetic-principal","synthetic-intent","synthetic-issuer","synthetic-source","synthetic-target",id(202),id(203),
                a.allowedAction(),a.customerId(),amount,id(2),id(303),a.evidenceBundleHash(),id(402),3,id(103),payload,a.policyVersion(),
                id(5),id(3),100,300);
        nodes.add(new SyntheticGrantChainStructure.Node(claims,a)); return nodes;
    }
    static SyntheticGrantIssuerBindings.Binding paymentBinding() {
        var b=VirtualGrantFactResolverTest.binding(2);
        return new SyntheticGrantIssuerBindings.Binding(b.subjectId(),b.actorId(),b.principalId(),b.issuerId(),
                SyntheticGrantIssuerBindings.Stage.MOCK_PAYMENT_EXECUTOR,AllowedAction.EXECUTE_MOCK_PAYMENT,
                b.customerId(),b.rootAuthorizationId(),b.workflowId(),b.intent(),b.keyReference());
    }
    static final class Local implements LocalPaymentFacts {
        Snapshot base; Snapshot secondBase; PaymentSnapshot payment; Snapshot lastLoaded; OwnedTx first;
        int loads,versions,paymentLoads,driftAt=Integer.MAX_VALUE;
        void begin() { first=null;lastLoaded=null;loads=0;versions=0;paymentLoads=0; }
        void same(OwnedTx tx) { if(first==null)first=tx;else assertSame(first,tx); }
        public Snapshot load(ServerContext context,StageCommand command,OwnedTx tx) {
            same(tx);loads++;if(loads==2 && secondBase!=null)base=secondBase;lastLoaded=base;return base;
        }
        public Fact versionChanged(ServerContext context,StageCommand command,OwnedTx tx,String version) {
            same(tx);assertEquals(base.version(),version);return ++versions>=driftAt?Fact.UNKNOWN:Fact.CLEAR;
        }
        public PaymentSnapshot loadPayment(ServerContext context,PaymentCommand command,OwnedTx tx,Snapshot exactBase) {
            same(tx);paymentLoads++;assertSame(lastLoaded,exactBase);return payment;
        }
    }
    static final class Fixture {
        // Public/package-visible data factories only; the helper's service/store are not used below.
        final VirtualGrantFactResolverTest.Fixture data=new VirtualGrantFactResolverTest.Fixture();
        final VirtualGrantFactResolverTest.CountingStore store=new VirtualGrantFactResolverTest.CountingStore();
        final VirtualGrantTransactionJournal journal=VirtualGrantTransactionJournal.detachedReference(store,()->id(900),65536);
        final Local local=new Local();
        final SyntheticGrantIssuerBindings.Prepared registry=SyntheticGrantIssuerBindings.prepare("synthetic-registry-version",
                List.of(VirtualGrantFactResolverTest.binding(1),VirtualGrantFactResolverTest.binding(2),paymentBinding()),
                new SyntheticGrantIssuerBindings.Limits(8,128));
        final GrantStageTransactionService stages=new GrantStageTransactionService(journal,new VirtualGrantFactResolver(registry,local));
        final VirtualMockPaymentFactResolver resolver=new VirtualMockPaymentFactResolver(registry,local);
        final SyntheticMockPaymentTransactionService service=new SyntheticMockPaymentTransactionService(journal,resolver);
        final GrantSnapshot paymentGrant=new GrantSnapshot(id(403),id(103),id(203),id(1),1,"synthetic-customer",
                AllowedAction.EXECUTE_MOCK_PAYMENT,GrantState.ISSUED);
        final PaymentDomain domain=new PaymentDomain(id(403),id(103),id(701),id(203),id(3),id(700),id(1),1,
                "synthetic-customer",id(702),1000L,id(2),"synthetic-policy",ReservationState.RESERVED,ApprovalState.RESERVED);
        final PaymentCommand command;
        Fixture() {
            journal.seedSyntheticRoot(data.root);local.base=data.snapshot(1);local.begin();
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,stages.completeStage(data.context,data.rootCommand,data.rootResult).status());
            Snapshot loan=data.snapshot(2);
            local.base=withIssuance(loan,new IssuanceFacts(data.root.grantId(),data.grant(2),VirtualGrantFactResolverTest.profile(),VirtualGrantFactResolverTest.chain(2)));
            local.begin();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,
                    stages.issueSuccessor(data.context,data.command(2,501),data.root.grantId(),data.grant(2)).status());
            local.base=loan;local.begin();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,
                    stages.completeStage(data.context,data.command(2,502),data.result(601)).status());
            Snapshot base=paymentBase(loan);
            local.base=withIssuance(base,new IssuanceFacts(data.grant(2).grantId(),paymentGrant,VirtualGrantFactResolverTest.profile(),paymentChain(1000)));
            var stage=new StageCommand(new SyntheticGrantReplayAssessment.CommandIdentity("synthetic-actor",id(503),"synthetic-payment",
                    "supplied-command-profile","supplied-command-digest",id(403),id(103),id(203),id(1),1,"synthetic-customer"),AllowedAction.EXECUTE_MOCK_PAYMENT);
            local.begin();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,
                    stages.issueSuccessor(data.context,stage,data.grant(2).grantId(),paymentGrant).status());
            journal.seedSyntheticPaymentDomain(domain);
            var complete=new StageCommand(new SyntheticGrantReplayAssessment.CommandIdentity("synthetic-actor",id(504),"synthetic-payment",
                    "supplied-command-profile","supplied-command-digest",id(403),id(103),id(203),id(1),1,"synthetic-customer"),AllowedAction.EXECUTE_MOCK_PAYMENT);
            var digest=new DigestBinding(complete.identity().canonicalBodyDigest(),"supplied-command-algorithm",new byte[]{1,2});
            var input=new SyntheticMockPaymentReceiptCodec.Input(id(504),"synthetic-actor","synthetic-payment","supplied-command-profile",
                    digest.algorithm(),digest.bytes(),id(403),id(103),id(701),id(203),id(3),id(700),id(1),1,"synthetic-customer",id(702),1000L,
                    id(2),"synthetic-policy","EXECUTE_MOCK_PAYMENT","COMMITTED","CONSUMED");
            command=new PaymentCommand(complete,digest,input);local.base=base;
            local.payment=new PaymentSnapshot(base.version(),VirtualGrantFactResolverTest.profile(),paymentChain(1000),
                    new ResolvedPayment(domain,digest,input,List.of()));local.begin();store.journalReads=0;
        }
        Snapshot withIssuance(Snapshot s,IssuanceFacts i) {
            return new Snapshot(s.version(),s.descriptor(),s.currentRead(),s.temporal(),s.revocation(),s.key(),null,i);
        }
        Snapshot paymentBase(Snapshot s) {
            return new Snapshot(s.version(),new Descriptor("synthetic-actor",paymentBinding(),"synthetic-owner-reference","synthetic-key-version"),
                    s.currentRead(),new SyntheticGrantTemporalAssessment.TemporalFacts(150,100,300,
                    SyntheticGrantTemporalAssessment.ChainPosition.CHILD,400L),s.revocation(),s.key(),null,null);
        }
        void replace(Descriptor d,SyntheticGrantReplayAssessment.CurrentReadFacts r,
                     SyntheticGrantTemporalAssessment.TemporalFacts time,KeyFacts key) {
            Snapshot s=local.base;local.base=new Snapshot(s.version(),d,r,time,s.revocation(),key,null,null);
        }
        StageOutcome complete() { local.begin();return service.completePayment(data.context,command); }
        StageOutcome reconcile() { local.begin();return service.reconcile(data.context,command); }
    }

    @Test void realResolverFreshPathCommitsWithoutForbiddenPostAdmissionLookupThenReplaysWithNoEffects() {
        Fixture f=new Fixture();StageOutcome first=f.complete();
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,first.status());assertEquals(1,f.local.paymentLoads);
        assertTrue(f.local.loads>=2);assertEquals("MP-COMMITTED-RECEIPT-1",first.receipt().result().bindingProfile());
        assertEquals(f.domain.paymentId(),first.receipt().result().resultId());
        assertFalse(first.actualAuthority());assertFalse(first.durable());
        var before=f.store.snapshot();StageOutcome replay=f.reconcile();
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,replay.status());assertEquals(first.receipt(),replay.receipt());
        assertEquals(0,f.local.paymentLoads);assertEquals(before,f.store.snapshot());
        assertEquals(3,before.get("virtual_grant_profile_grants").size());
        assertFalse(f.resolver.actualAuthorizationEstablished());assertFalse(f.resolver.actualRegistryProvenanceEstablished());
        assertFalse(f.resolver.executionAuthorityGranted());
        // Actual journal rejects lookup after admitFresh; success cannot hide an extra such lookup.
    }

    @Test void commonAliasOwnerOrMissingKeyDenialHappensBeforeJournalLookup() {
        for(int mode=0;mode<4;mode++) {
            Fixture f=new Fixture();Snapshot b=f.local.base;Descriptor d=b.descriptor();KeyFacts k=b.key();
            if(mode==0)d=new Descriptor("other-alias",d.issuerBinding(),d.keyOwnerReference(),d.keyVersion());
            if(mode==1)d=new Descriptor(d.actorAlias(),d.issuerBinding(),"other-owner",d.keyVersion());
            if(mode==2)k=null;
            if(mode==3)d=new Descriptor(d.actorAlias(),d.issuerBinding(),d.keyOwnerReference(),"other-key-version");
            f.replace(d,b.currentRead(),b.temporal(),k);var before=f.store.snapshot();
            assertEquals(mode==0?Status.REFUSED_BEFORE_ADMISSION:Status.UNCONFIRMED_BEFORE_ADMISSION,f.complete().status());
            assertEquals(0,f.store.journalReads);assertEquals(0,f.local.paymentLoads);assertEquals(before,f.store.snapshot());
        }
    }

    @Test void baseVersionTicketDriftAndMissingPaymentSnapshotRollBackFreshAdmission() {
        for(int mode=0;mode<4;mode++) {
            Fixture f=new Fixture();PaymentSnapshot p=f.local.payment;
            if(mode==0)f.local.payment=new PaymentSnapshot("other-version",p.codecProfile(),p.nodes(),p.resolved());
            if(mode==1)f.local.payment=null;
            if(mode==2)f.local.driftAt=4;
            if(mode==3)f.local.driftAt=1;
            var before=f.store.snapshot();assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,f.complete().status());
            assertEquals(before,f.store.snapshot());assertEquals(mode==3?0:1,f.local.paymentLoads);
            if(mode==3)assertEquals(0,f.store.journalReads);
        }
    }

    @Test void retiredOutstandingNeedsBeforeOrderingAndAvailableMaterial() {
        for(int mode=0;mode<3;mode++) {
            Fixture f=new Fixture();Snapshot b=f.local.base;
            f.replace(b.descriptor(),b.currentRead(),b.temporal(),VirtualGrantFactResolverTest.key(
                    SyntheticGrantKeyLifecycleAssessment.Lifecycle.RETIRED,
                    mode==0?SyntheticGrantKeyLifecycleAssessment.Ordering.AT_RETIREMENT:SyntheticGrantKeyLifecycleAssessment.Ordering.BEFORE_RETIREMENT,
                    mode==2?SyntheticGrantKeyLifecycleAssessment.MaterialFact.UNKNOWN:SyntheticGrantKeyLifecycleAssessment.MaterialFact.AVAILABLE));
            var before=f.store.snapshot();StageOutcome result=f.complete();
            assertEquals(mode==1?Status.VIRTUAL_COMMITTED_IN_PROCESS:Status.UNCONFIRMED_BEFORE_ADMISSION,result.status());
            if(mode!=1)assertEquals(before,f.store.snapshot());
        }
    }

    @Test void fullPaymentChainAndItsLeafAmountMustMatchDomain() {
        for(boolean missingRoot:List.of(false,true)) {
            Fixture f=new Fixture();PaymentSnapshot p=f.local.payment;
            List<SyntheticGrantChainStructure.Node> nodes=missingRoot?p.nodes().subList(1,3):paymentChain(1001);
            f.local.payment=new PaymentSnapshot(p.baseVersion(),p.codecProfile(),nodes,p.resolved());
            var before=f.store.snapshot();assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,f.complete().status());
            assertEquals(before,f.store.snapshot());
        }
    }

    @Test void actualReservedPlanAndExpectedMp22DigestCannotBeSubstitutedBySuppliedSnapshots() {
        for(int mode=0;mode<3;mode++) {
            Fixture f=new Fixture();PaymentSnapshot p=f.local.payment;ResolvedPayment r=p.resolved();
            if(mode==0)f.store.transaction(tx->{var row=new LinkedHashMap<>(tx.get("virtual_grant_profile_payment_plans",f.domain.reservationId().toString()));
                row.put("amountKrw",1001L);tx.put("virtual_grant_profile_payment_plans",f.domain.reservationId().toString(),row);return null;});
            if(mode==1)r=new ResolvedPayment(r.domain(),r.commandDigest(),SyntheticMockPaymentTransactionBindingTest.changed(r.receiptInput(),17),r.applicableDomainWrites());
            if(mode==2)r=new ResolvedPayment(r.domain(),new DigestBinding(r.commandDigest().identityDigestReference(),r.commandDigest().algorithm(),new byte[]{9}),r.receiptInput(),r.applicableDomainWrites());
            f.local.payment=new PaymentSnapshot(p.baseVersion(),p.codecProfile(),p.nodes(),r);
            var before=f.store.snapshot();assertEquals(Status.UNCONFIRMED_BEFORE_ADMISSION,f.complete().status());
            assertEquals(before,f.store.snapshot());
        }
    }

    @Test void ownExpiredPaymentHistoryDoesNotRequireOutstandingMaterialButAncestorDenialStillBlocks() {
        Fixture f=new Fixture();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,f.complete().status());
        Snapshot b=f.local.base;f.replace(b.descriptor(),b.currentRead(),new SyntheticGrantTemporalAssessment.TemporalFacts(300,100,300,
                SyntheticGrantTemporalAssessment.ChainPosition.CHILD,400L),VirtualGrantFactResolverTest.key(
                SyntheticGrantKeyLifecycleAssessment.Lifecycle.RETIRED,SyntheticGrantKeyLifecycleAssessment.Ordering.UNKNOWN,
                SyntheticGrantKeyLifecycleAssessment.MaterialFact.UNKNOWN));
        f.local.payment=null;var before=f.store.snapshot();
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,f.reconcile().status());assertEquals(0,f.local.paymentLoads);
        Snapshot expired=f.local.base;f.replace(expired.descriptor(),VirtualGrantFactResolverTest.reads(Fact.ACTIVE),expired.temporal(),expired.key());
        f.store.journalReads=0;assertEquals(Status.REFUSED_BEFORE_ADMISSION,f.reconcile().status());
        assertEquals(0,f.store.journalReads);assertEquals(before,f.store.snapshot());
    }
    @Test void freshReloadRechecksKnownDenialWithoutCallingHistoricalLookupAfterAdmission() {
        Fixture f=new Fixture();Snapshot b=f.local.base;Descriptor d=b.descriptor();
        f.local.secondBase=new Snapshot(b.version(),new Descriptor("other-alias",d.issuerBinding(),d.keyOwnerReference(),d.keyVersion()),
                b.currentRead(),b.temporal(),b.revocation(),b.key(),null,null);
        var before=f.store.snapshot();StageOutcome denied=f.complete();
        assertEquals(Status.REFUSED_BEFORE_ADMISSION,denied.status());assertNull(denied.receipt());
        assertEquals(2,f.local.loads);assertEquals(0,f.local.paymentLoads);assertEquals(before,f.store.snapshot());
    }

    static SyntheticGrantChainStructure.Node retimed(SyntheticGrantChainStructure.Node node,long issued,long expires) {
        var c=node.claims();
        var changed=new SyntheticGrantV2Codec.Claims(c.format(),c.algorithm(),c.kid(),c.grantId(),c.workflowId(),c.generation(),
                c.rootAuthorizationId(),c.principalId(),c.originIntent(),c.issuer(),c.sourceAgent(),c.targetAgent(),c.sourceRunId(),
                c.targetRunId(),c.allowedAction(),c.customerId(),c.amountKrw(),c.payoutAccountId(),c.sourceResultId(),
                c.evidenceBundleHash(),c.parentGrantId(),c.depth(),c.actionId(),c.payloadHash(),c.policyVersion(),
                c.riskLedgerId(),c.approvalId(),issued,expires);
        return new SyntheticGrantChainStructure.Node(changed,node.action());
    }

    @Test void suppliedParentCapOrRootLabelCannotOverrideActualPaymentChainAncestry() {
        for(int mode=0;mode<3;mode++) {
            Fixture f=new Fixture();Snapshot b=f.local.base;PaymentSnapshot p=f.local.payment;
            var nodes=new ArrayList<>(p.nodes());
            nodes.set(0,retimed(nodes.get(0),10,40));
            nodes.set(1,retimed(nodes.get(1),10,mode==2?40:20));
            nodes.set(2,retimed(nodes.get(2),10,30));
            f.local.payment=new PaymentSnapshot(p.baseVersion(),p.codecProfile(),nodes,p.resolved());
            f.replace(b.descriptor(),b.currentRead(),new SyntheticGrantTemporalAssessment.TemporalFacts(15,10,30,
                    mode==1?SyntheticGrantTemporalAssessment.ChainPosition.ROOT:SyntheticGrantTemporalAssessment.ChainPosition.CHILD,
                    mode==1?null:40L),b.key());
            var before=f.store.snapshot();StageOutcome outcome=f.complete();
            assertEquals(mode==2?Status.VIRTUAL_COMMITTED_IN_PROCESS:Status.UNCONFIRMED_BEFORE_ADMISSION,outcome.status());
            assertEquals(1,f.local.paymentLoads);
            if(mode!=2){assertNull(outcome.receipt());assertEquals(before,f.store.snapshot());}
        }
    }

}
