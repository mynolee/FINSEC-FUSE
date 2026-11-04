package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.persistence.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionService.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBindingTest.*;
import static com.finsec.fuse.reimplementation.grant.VirtualGrantFactResolverTest.id;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static org.junit.jupiter.api.Assertions.*;

/** In-memory owned root composition; no real issuer, role, database or durable commit. */
final class SyntheticRootProvisionServiceTest {
    static final class Store implements TransactionalStore {
        final VirtualTransactionalStore delegate = new VirtualTransactionalStore();
        Tx active; int journalReads, writes, failWrite = Integer.MAX_VALUE; boolean afterCommit;
        public String mode() { return delegate.mode(); }
        public Map<String,Map<String,Map<String,Object>>> snapshot() { return delegate.snapshot(); }
        public <T> T transaction(Function<Tx,T> work) {
            try {
                T result = delegate.transaction(tx -> {
                    active = new Tx() {
                        public Map<String,Object> get(String table,String key) {
                            if (table.equals(ActionJournal.TABLE)) journalReads++; return tx.get(table,key);
                        }
                        public Map<String,Map<String,Object>> rows(String table) { return tx.rows(table); }
                        public void put(String table,String key,Map<String,Object> value) {
                            if (++writes == failWrite) throw new IllegalStateException("synthetic-write-failure");
                            tx.put(table,key,value);
                        }
                    };
                    return work.apply(active);
                });
                if (afterCommit) { afterCommit=false; throw new IllegalStateException("synthetic-lost-ack"); }
                return result;
            } finally { active=null; }
        }
    }
    static final class Resolver implements CurrentRootFactResolver {
        final RootFixture f; Gate gate=Gate.CLEAR; int checks,resolutions; boolean wrongTicket,wrongSubject,lateDeny;
        OwnedRootProvisionPort.OwnedRootTx first; CurrentBindings ticket; Runnable duringResolve=()->{};
        Resolver(RootFixture f) { this.f=f; }
        void same(OwnedRootProvisionPort.OwnedRootTx tx) { if(first==null) first=tx; else assertSame(first,tx); }
        public Gate current(RootServerContext context,RootCommand command,OwnedRootProvisionPort.OwnedRootTx tx) {
            same(tx); checks++; return lateDeny && checks==2 ? Gate.REFUSED : gate;
        }
        public ResolvedRootProvision resolve(RootServerContext context,RootCommand command,CurrentBindings bindings,
                                             OwnedRootProvisionPort.OwnedRootTx tx) {
            same(tx); resolutions++; ticket=bindings; duringResolve.run();
            return f.resolved(wrongTicket ? absent() : bindings);
        }
        void next() { first=null; }
    }
    static final class Fixture {
        final RootFixture data=new RootFixture(); final Store store=new Store(); final Resolver resolver=new Resolver(data);
        final AtomicInteger tokens=new AtomicInteger(900);
        final VirtualGrantTransactionJournal journal=new VirtualGrantTransactionJournal(store,()->id(tokens.incrementAndGet()),65536);
        final SyntheticRootProvisionService service=new SyntheticRootProvisionService(journal,resolver);
        final RootServerContext actor=new RootServerContext() {
            public String actorId() { return data.identity.actorId(); }
            public String subjectId() { return data.issuer.binding().subjectId(); }
        };
        RootOutcome provision() { resolver.next(); return service.provisionRoot(actor,data.command); }
        RootOutcome reconcile() { resolver.next(); return service.reconcileRoot(actor,data.command); }
    }
    private static void noReceipt(RootOutcome value,Status status) {
        assertEquals(status,value.status()); assertNull(value.receipt()); assertFalse(value.actualAuthority()); assertFalse(value.durable());
    }

    @Test void actualJournalInitializesWorkflowTypedLaneAndIssuedRootAtomicallyWithoutKycDispatch() {
        var f=new Fixture(); var outcome=f.provision();
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,outcome.status()); assertTrue(outcome.receipt().matches(f.data.command));
        assertFalse(outcome.actualAuthority()); assertFalse(outcome.durable()); assertEquals(2,f.resolver.checks);
        assertEquals(1,f.resolver.resolutions); assertTrue(f.resolver.ticket.allAbsent());
        var tables=f.store.snapshot(); var workflow=tables.get("virtual_workflows").get(f.data.plan.workflowId().toString());
        assertEquals("KYC_PENDING",workflow.get("state")); assertNull(workflow.get("activeJobId"));
        assertNull(workflow.get("currentKycResultId")); assertEquals(0,workflow.get("usedRisk"));
        assertEquals("TYPED",tables.get("virtual_workflow_lanes").get(f.data.plan.workflowId().toString()).get("lane"));
        assertEquals("ISSUED",tables.get("virtual_grant_profile_grants").get(f.data.identity.grantId().toString()).get("state"));
        for(String table:List.of("virtual_jobs","virtual_runs","virtual_results","virtual_grant_profile_results","virtual_grant_profile_successors"))
            assertTrue(tables.getOrDefault(table,Map.of()).isEmpty());
        var encoded=CanonicalJson.write(tables.get("virtual_grant_profile_root_receipts"));
        assertFalse(encoded.contains(f.data.source.text())); assertTrue(encoded.contains(f.data.source.contentHash()));
    }

    @Test void currentDenialPrecedesAnyCachedJournalReadAndReceiptDisclosure() {
        var f=new Fixture(); f.provision(); var before=f.store.snapshot();
        for(Gate gate:List.of(Gate.REFUSED,Gate.UNKNOWN)) {
            f.resolver.gate=gate; f.store.journalReads=0;
            noReceipt(f.provision(),gate==Gate.REFUSED?Status.REFUSED_BEFORE_ADMISSION:Status.UNCONFIRMED_BEFORE_ADMISSION);
            assertEquals(0,f.store.journalReads); assertEquals(before,f.store.snapshot()); assertEquals(1,f.resolver.resolutions);
        }
    }

    @Test void exactReplayAndReconcileHaveNoNewResolutionOrInitialization() {
        var f=new Fixture(); var first=f.provision(); var before=f.store.snapshot();
        var replay=f.provision(); var reconciled=f.reconcile();
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,replay.status()); assertEquals(first.receipt(),replay.receipt());
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,reconciled.status());
        assertEquals(before,f.store.snapshot()); assertEquals(1,f.resolver.resolutions);
    }

    @Test void everyIdentityReplacementCannotReplayRootPurposeReceipt() throws Exception {
        String[] fields={"actorId","globalRequestId","operation","canonicalizationVersion","canonicalBodyDigest"};
        for(String field:fields) {
            var f=new Fixture(); f.provision(); var before=f.store.snapshot();
            Object replacement=field.equals("globalRequestId")?id(999):"synthetic-other";
            var identity=changed(f.data.identity,field,replacement);
            var command=new RootCommand(identity,f.data.inputs,f.data.plan); f.resolver.next();
            var result=f.service.provisionRoot(f.actor,command);
            assertNotEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,result.status());
            assertNotEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,result.status()); assertNull(result.receipt());
            assertEquals(before,f.store.snapshot());
        }
        // The other six identity/scope replacements fail RootCommand construction in the binding suite.
    }

    @Test void sameFacadeTicketIsRequiredEvenWithIdenticalAllAbsentFlags() {
        var f=new Fixture(); f.resolver.wrongTicket=true; var before=f.store.snapshot();
        noReceipt(f.provision(),Status.UNCONFIRMED_BEFORE_ADMISSION); assertEquals(before,f.store.snapshot());
    }

    @Test void secondCurrentCheckAndSubjectMismatchRollbackPositiveAdmission() {
        var f=new Fixture(); f.resolver.lateDeny=true; var before=f.store.snapshot();
        noReceipt(f.provision(),Status.REFUSED_BEFORE_ADMISSION); assertEquals(before,f.store.snapshot());
        var g=new Fixture(); RootServerContext otherSubject=new RootServerContext() {
            public String actorId(){return g.data.identity.actorId();} public String subjectId(){return "synthetic-other-subject";}
        };
        noReceipt(g.service.provisionRoot(otherSubject,g.data.command),Status.UNCONFIRMED_BEFORE_ADMISSION);
        assertTrue(g.store.snapshot().isEmpty());
    }

    @Test void collisionIntroducedAfterTicketIsRecheckedInSameTransactionAndAllWritesRollback() {
        var f=new Fixture(); var before=f.store.snapshot();
        f.resolver.duringResolve=()->f.store.active.put("virtual_workflows",f.data.plan.workflowId().toString(),
                Map.of("workflowId",f.data.plan.workflowId().toString(),"generation",1,"customerId",f.data.application.customerId(),
                        "businessReference",f.data.application.businessReference()));
        noReceipt(f.provision(),Status.UNCONFIRMED_BEFORE_ADMISSION); assertEquals(before,f.store.snapshot());
    }

    @Test void partialWriteFailureHasNoCommittedWorkflowLaneRootOrGlobalReceipt() {
        var f=new Fixture(); f.store.failWrite=3; var before=f.store.snapshot();
        noReceipt(f.provision(),Status.UNCONFIRMED_BEFORE_ADMISSION);
        assertEquals(3,f.store.writes); assertEquals(before,f.store.snapshot());
    }

    @Test void unknownCommitBlocksFreshWorkAndExactReconcileUsesActualStoredRootReceipt() throws Exception {
        var f=new Fixture(); f.store.afterCommit=true;
        noReceipt(f.provision(),Status.COMMIT_UNKNOWN); var committed=f.store.snapshot();
        assertFalse(committed.isEmpty());
        // A new UUID has no completed/pending journal entry, but must not bypass the
        // same-root uncertainty barrier before the original exact reconciliation.
        var nextIdentity=changed(f.data.identity,"globalRequestId",id(999));
        var nextCommand=new RootCommand(nextIdentity,f.data.inputs,f.data.plan);
        assertFalse(committed.get(ActionJournal.TABLE).containsKey(nextIdentity.globalRequestId().toString()));
        int checks=f.resolver.checks, writes=f.store.writes, tokens=f.tokens.get();
        f.store.journalReads=0; f.resolver.next();
        var blocked=f.service.provisionRoot(f.actor,nextCommand);
        noReceipt(blocked,Status.RECONCILIATION_UNCONFIRMED);
        assertEquals(RootEffect.UNKNOWN,blocked.effectKnowledge());
        assertEquals(checks+1,f.resolver.checks); assertTrue(f.store.journalReads>0);
        assertEquals(1,f.resolver.resolutions); assertEquals(tokens,f.tokens.get());
        assertEquals(writes,f.store.writes); assertEquals(committed,f.store.snapshot());
        var reconciled=f.reconcile();
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,reconciled.status());
        assertEquals(committed,f.store.snapshot()); assertEquals(1,f.resolver.resolutions);
    }

    @Test void phaseOrderDetachedContextAndOrdinaryGlobalUuidConflictsCannotCreateRoot() {
        var f=new Fixture(); var before=f.store.snapshot();
        noReceipt(f.journal.provisionRoot(f.data.command,tx->{tx.admitFreshRoot(f.data.command);
            return new RootOutcome(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH,null,RootEffect.UNKNOWN);}),Status.RECONCILIATION_UNCONFIRMED);
        assertEquals(before,f.store.snapshot());
        var detached=VirtualGrantTransactionJournal.detachedReference(f.store,()->id(999),65536);
        noReceipt(detached.provisionRoot(f.data.command,tx->{fail("detached callback must not run");return null;}),Status.UNCONFIRMED_BEFORE_ADMISSION);
        new ActionJournal(f.store).execute(f.data.identity.actorId(),f.data.identity.globalRequestId(),"synthetic-other-operation","b".repeat(64),
                tx->Map.of("requestId",f.data.identity.globalRequestId().toString(),"synthetic","occupied"));
        var occupied=f.store.snapshot(); noReceipt(f.provision(),Status.IDENTITY_CONFLICT);
        assertEquals(occupied,f.store.snapshot()); assertEquals(0,f.resolver.resolutions);
    }
}
