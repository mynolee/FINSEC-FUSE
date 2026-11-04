package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec.RiskTerms;
import com.finsec.fuse.reimplementation.simulation.VirtualWorkflowLane.Scope;
import com.finsec.fuse.reimplementation.simulation.VirtualGrantContinuationFixture;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import static com.finsec.fuse.reimplementation.grant.VirtualGrantGenerationHistory.*;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic structural regressions; source only, NOT_RUN. No authority or durable-store proof. */
final class VirtualGrantGenerationHistoryTest {
    private static UUID id(long n) { return new UUID(0,n); }
    private static Scope scope(int generation) { return new Scope(id(1),generation,"synthetic-customer"); }
    private static RiskTerms terms() { return new RiskTerms("synthetic-policy",1,1,1,10,5,1,Duration.ofSeconds(60)); }
    private static GenerationRecord record(int generation, Instant at) {
        return new GenerationRecord(scope(generation),id(2),id(3),id(4),id(5),1,terms(),at);
    }
    private static void invalid(Executable work) {
        var error=assertThrows(IllegalArgumentException.class,work);
        assertEquals("INVALID_GENERATION_HISTORY",error.getMessage()); assertNull(error.getCause());
    }
    private static Map<String,Object> head() {
        var row=new LinkedHashMap<String,Object>();
        row.put("workflowId",id(1).toString()); row.put("generation",1);
        row.put("customerId","synthetic-customer"); row.put("rootGrantId",id(2).toString());
        row.put("revision",0L); return row;
    }
    private static void putHead(VirtualTransactionalStore store,Map<String,Object> row) {
        store.transaction(tx->{tx.put("virtual_grant_profile_current_heads",id(1).toString(),row);return null;});
    }
    private static VirtualTransactionalStore current(int generation) {
        var store=new VirtualTransactionalStore();
        store.transaction(tx->{
            var row=Map.<String,Object>of("workflowId",id(1).toString(),"generation",generation,"customerId","synthetic-customer");
            tx.put("virtual_workflows",id(1).toString(),row);
            var lane=new LinkedHashMap<>(row); lane.put("lane","TYPED");
            tx.put("virtual_workflow_lanes",id(1).toString(),lane); return null;
        }); return store;
    }
    @Test void absentHeadIsNotAnAllocatedZeroRevision() {
        var store=new VirtualTransactionalStore();
        store.transaction(tx->{assertNull(readHead(tx,id(1)));return null;});
        putHead(store,head());
        store.transaction(tx->{assertEquals(new ExpectedHead(scope(1),id(2),0),readHead(tx,id(1)));return null;});
    }
    @Test void headRequiresClosedNativeLongRevisionAndPositiveGeneration() {
        for(Object value:new Object[]{0, -1L, "0", true}) {
            var store=new VirtualTransactionalStore();var row=head();row.put("revision",value);putHead(store,row);
            store.transaction(tx->{invalid(()->readHead(tx,id(1)));return null;});
        }
        for(Object value:new Object[]{0,-1,1L,"1",true}) {
            var store=new VirtualTransactionalStore();var row=head();row.put("generation",value);putHead(store,row);
            store.transaction(tx->{invalid(()->readHead(tx,id(1)));return null;});
        }
        var store=new VirtualTransactionalStore();var row=head();row.put("future",true);putHead(store,row);
        store.transaction(tx->{invalid(()->readHead(tx,id(1)));return null;});
    }
    @Test void headKeyMustMatchCanonicalWorkflowIdentity() {
        var store=new VirtualTransactionalStore();var row=head();row.put("workflowId",id(9).toString());putHead(store,row);
        store.transaction(tx->{invalid(()->readHead(tx,id(1)));return null;});
        var malformed=new VirtualTransactionalStore();row=head();row.put("rootGrantId","not-a-uuid");putHead(malformed,row);
        malformed.transaction(tx->{invalid(()->readHead(tx,id(1)));return null;});
    }
    @Test void maximumRevisionIsRepresentableWithoutInventingAnIncrement() {
        var store=new VirtualTransactionalStore();var row=head();row.put("revision",Long.MAX_VALUE);putHead(store,row);
        store.transaction(tx->{assertEquals(Long.MAX_VALUE,readHead(tx,id(1)).revision());return null;});
        invalid(()->new ExpectedHead(scope(1),id(2),-1));
    }
    @Test void firstGenerationFenceDoesNotManufactureHistoryOrObservation() {
        var store=current(1);var before=store.snapshot();
        store.transaction(tx->{checkCurrentScope(tx,scope(1));assertNull(readHead(tx,id(1)));return null;});
        assertEquals(before,store.snapshot());
        assertNull(record(1,null).observedAt());
        store.transaction(tx->{invalid(()->establishOriginal(tx,record(1,null),0));return null;});
        assertEquals(before,store.snapshot());
    }
    @Test void laterGenerationAbsenceCannotFallBackToOriginalOrFence() {
        var store=current(2);var before=store.snapshot();
        store.transaction(tx->{invalid(()->checkCurrentScope(tx,scope(2)));invalid(()->validate(tx,scope(2)));return null;});
        assertEquals(before,store.snapshot());
    }
    @Test void currentFenceRejectsForeignCustomerGenerationAndMissingLaneWithoutWrites() {
        var store=current(1);var before=store.snapshot();
        store.transaction(tx->{invalid(()->checkCurrentScope(tx,new Scope(id(1),1,"foreign")));
            invalid(()->checkCurrentScope(tx,scope(2)));return null;});
        assertEquals(before,store.snapshot());
        var empty=new VirtualTransactionalStore();empty.transaction(tx->{invalid(()->checkCurrentScope(tx,scope(1)));return null;});
        assertTrue(empty.snapshot().isEmpty());
    }
    @Test void immutableRecordsUseFixedRedactedDiagnosticsAndRequireExplicitFields() {
        var observed=record(1,Instant.ofEpochSecond(150));
        assertEquals(scope(1),observed.scope());assertEquals(terms(),observed.terms());
        assertEquals("GenerationRecord[REDACTED]",observed.toString());
        assertEquals("ExpectedHead[REDACTED]",new ExpectedHead(scope(1),id(2),0).toString());
        invalid(()->new GenerationRecord(scope(1),id(2),id(3),id(4),id(5),0,terms(),Instant.EPOCH));
        invalid(()->new GenerationRecord(scope(1),null,id(3),id(4),id(5),1,terms(),Instant.EPOCH));
    }
    private static SyntheticRootProvisionServiceTest.Fixture rooted() {
        var f=new SyntheticRootProvisionServiceTest.Fixture();
        assertEquals(OwnedGrantTransactionPort.Status.VIRTUAL_COMMITTED_IN_PROCESS,f.provision().status());
        return f;
    }
    private static Scope actualScope(SyntheticRootProvisionServiceTest.Fixture f) {
        return new Scope(f.data.plan.workflowId(),1,f.data.application.customerId());
    }
    private static GenerationRecord actualRecord(SyntheticRootProvisionServiceTest.Fixture f,Instant observed) {
        return new GenerationRecord(actualScope(f),f.data.identity.grantId(),f.data.identity.globalRequestId(),
                f.data.identity.targetRunId(),f.data.source.documentId(),f.data.source.documentVersion(),f.data.terms,observed);
    }
    @Test void actualPublicRootOriginProjectsWithoutInventingObservedHeadOrTimestamp() {
        var f=rooted(); var before=f.store.snapshot();
        f.store.transaction(tx->{
            assertEquals(actualRecord(f,null),validate(tx,actualScope(f)));
            assertEquals(actualRecord(f,null),requireCurrent(tx,actualScope(f)));
            assertNull(readHead(tx,f.data.plan.workflowId()));return null;
        });
        assertEquals(before,f.store.snapshot());
    }
    @Test void observedOriginalCreatesExplicitZeroHeadAndImmutableRowsFromRealOrigin() {
        var f=rooted();var observed=actualRecord(f,Instant.ofEpochSecond(151));
        f.store.transaction(tx->{
            assertEquals(new ExpectedHead(actualScope(f),f.data.identity.grantId(),0),establishOriginal(tx,observed,0));
            assertEquals(observed,requireCurrent(tx,actualScope(f)));return null;
        });
        var before=f.store.snapshot();
        f.store.transaction(tx->{invalid(()->establishOriginal(tx,observed,0));return null;});
        assertEquals(before,f.store.snapshot());
        var row=before.get("virtual_grant_profile_generations").get(f.data.plan.workflowId()+":1");
        assertThrows(UnsupportedOperationException.class,()->row.put("observedAt","changed"));
        assertThrows(UnsupportedOperationException.class,()->((Map<?,?>)row.get("terms")).clear());
    }
    @Test void changedRootTargetSourceAndCustomerCannotAuthenticateAgainstActualOrigin() {
        for(int mode=0;mode<5;mode++) {
            var f=rooted();var r=actualRecord(f,Instant.ofEpochSecond(151));
            var changed=new GenerationRecord(mode==4?new Scope(r.scope().workflowId(),1,"foreign"):r.scope(),
                    mode==0?id(991):r.rootGrantId(),r.rootRequestId(),mode==1?id(992):r.rootTargetRunId(),
                    mode==2?id(993):r.sourceDocId(),mode==3?r.sourceVersion()+1:r.sourceVersion(),r.terms(),r.observedAt());
            var before=f.store.snapshot();
            // Both origin lookup and current-fence refusal must leave the committed store unchanged.
            f.store.transaction(tx->{assertThrows(RuntimeException.class,()->establishOriginal(tx,changed,0));return null;});
            assertEquals(before,f.store.snapshot());
        }
    }
    @Test void stagedObservationRollsBackWithCallerTransactionFailure() {
        var f=rooted();var before=f.store.snapshot();var sentinel=new IllegalStateException("synthetic-rollback");
        assertSame(sentinel,assertThrows(IllegalStateException.class,()->f.store.transaction(tx->{
            establishOriginal(tx,actualRecord(f,Instant.ofEpochSecond(151)),7);throw sentinel;
        })));
        assertEquals(before,f.store.snapshot());
        f.store.transaction(tx->{assertNull(readHead(tx,f.data.plan.workflowId()));return null;});
    }
    @Test void staleHeadCasRefusesBeforeNextOriginOrAnyWrite() {
        var f=rooted();var old=actualRecord(f,Instant.ofEpochSecond(151));
        f.store.transaction(tx->{establishOriginal(tx,old,7);return null;});var before=f.store.snapshot();
        var next=new GenerationRecord(new Scope(old.scope().workflowId(),2,old.scope().customerId()),
                id(991),id(992),id(993),old.sourceDocId(),old.sourceVersion(),old.terms(),Instant.ofEpochSecond(152));
        f.store.transaction(tx->{invalid(()->advance(tx,new ExpectedHead(old.scope(),old.rootGrantId(),6),next));return null;});
        assertEquals(before,f.store.snapshot());
    }
    @Test void maximumAllocatedRevisionRejectsCheckedAdvanceWithoutPublishingNextRows() {
        var f=rooted();var old=actualRecord(f,Instant.ofEpochSecond(151));
        f.store.transaction(tx->{establishOriginal(tx,old,Long.MAX_VALUE);return null;});var before=f.store.snapshot();
        var next=new GenerationRecord(new Scope(old.scope().workflowId(),2,old.scope().customerId()),
                id(991),id(992),id(993),old.sourceDocId(),old.sourceVersion(),old.terms(),Instant.ofEpochSecond(152));
        f.store.transaction(tx->{invalid(()->advance(tx,new ExpectedHead(old.scope(),old.rootGrantId(),Long.MAX_VALUE),next));return null;});
        assertEquals(before,f.store.snapshot());
    }

    @Test void storedGenerationSchemaRejectsNonNativeAndNonCanonicalDataBeforeOrigin() {
        for(int index=0;index<7;index++) {
            final int mode=index;
            var f=rooted();var observed=actualRecord(f,Instant.ofEpochSecond(151));
            f.store.transaction(tx->{establishOriginal(tx,observed,0);return null;});
            f.store.transaction(tx->{
                String key=f.data.plan.workflowId()+":1";
                var row=new LinkedHashMap<>(tx.get("virtual_grant_profile_generations",key));
                switch(mode) {
                    case 0 -> row.put("generation",1L);
                    case 1 -> row.put("sourceVersion",true);
                    case 2 -> row.put("observedAt","1970-01-01T00:02:31.000Z");
                    case 3 -> row.put("future",true);
                    case 4 -> row.remove("rootRequestId");
                    case 5 -> row.put("rootTargetRunId","not-a-uuid");
                    default -> {var risk=new LinkedHashMap<String,Object>();
                        ((Map<?,?>)row.get("terms")).forEach((k,v)->risk.put((String)k,v));
                        risk.put("kycPoints",1L);row.put("terms",risk);}
                }
                tx.put("virtual_grant_profile_generations",key,row);return null;
            });
            var before=f.store.snapshot();
            f.store.transaction(tx->{invalid(()->validate(tx,actualScope(f)));return null;});
            assertEquals(before,f.store.snapshot());
        }
    }

    @Test void actualContinuationPublishesGenerationTwoWithAnchoredOriginalAndExactHead() {
        var f=new VirtualGrantContinuationFixture();
        f.blockAndRelease();var command=f.firstCommand();var outcome=f.advance(command);
        assertEquals(com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.Status.VIRTUAL_COMMITTED_IN_PROCESS,outcome.status());
        assertNotNull(outcome.receipt());
        var before=f.store.snapshot();
        f.store.transaction(tx->{
            var original=validate(tx,f.scope(1));var current=requireCurrent(tx,f.scope(2));
            assertEquals(f.oldRootCommand.identity().grantId(),original.rootGrantId());
            assertEquals(f.oldRootCommand.identity().globalRequestId(),original.rootRequestId());
            assertEquals(f.oldRootCommand.workflowPlan().application().source().documentId(),original.sourceDocId());
            assertEquals(command.identity().grantId(),current.rootGrantId());
            assertEquals(command.identity().globalRequestId(),current.rootRequestId());
            assertEquals(command.identity().targetRunId(),current.rootTargetRunId());
            assertEquals(command.application().source().documentId(),current.sourceDocId());
            assertEquals(command.application().source().documentVersion(),current.sourceVersion());
            assertEquals(command.observedAt(),current.observedAt());assertNotNull(original.observedAt());
            assertEquals(original.terms(),current.terms());assertEquals(f.terms,current.terms());
            assertEquals(new ExpectedHead(f.scope(2),command.identity().grantId(),1),readHead(tx,f.scope(2).workflowId()));
            invalid(()->requireCurrent(tx,f.scope(1)));return null;
        });
        assertEquals(before,f.store.snapshot());
    }
    @Test void laterAdvanceKeepsOldGenerationReadableWithoutTreatingItAsCurrent() {
        var f=new VirtualGrantContinuationFixture();f.blockAndRelease();
        var second=f.advance(f.firstCommand());
        assertEquals(com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.Status.VIRTUAL_COMMITTED_IN_PROCESS,second.status());
        GenerationRecord old=f.store.transaction(tx->validate(tx,f.scope(2)));
        f.blockAndRelease();var command=f.command(3,f.expected(second.receipt()),6003);
        var third=f.advance(command);
        assertEquals(com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.Status.VIRTUAL_COMMITTED_IN_PROCESS,third.status());
        var before=f.store.snapshot();
        f.store.transaction(tx->{
            assertEquals(old,validate(tx,f.scope(2)));
            assertEquals(command.identity().grantId(),requireCurrent(tx,f.scope(3)).rootGrantId());
            assertEquals(2L,readHead(tx,f.scope(3).workflowId()).revision());
            invalid(()->requireCurrent(tx,f.scope(2)));return null;
        });assertEquals(before,f.store.snapshot());
    }
    @Test void historicalValidationNeedsGenerationOneAnchorEvenWithCoherentCurrentGeneration() {
        var f=new VirtualGrantContinuationFixture();f.blockAndRelease();
        assertEquals(com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.Status.VIRTUAL_COMMITTED_IN_PROCESS,f.advance(f.firstCommand()).status());
        // Corrupt only the existing original observation, not a fabricated origin or success row.
        f.store.transaction(tx->{
            String key=f.scope(1).workflowId()+":1";
            var row=new LinkedHashMap<>(tx.get("virtual_grant_profile_generations",key));
            row.put("sourceDocId",id(99999).toString());tx.put("virtual_grant_profile_generations",key,row);return null;
        });var before=f.store.snapshot();
        f.store.transaction(tx->{assertThrows(RuntimeException.class,()->validate(tx,f.scope(2)));
            assertThrows(RuntimeException.class,()->requireCurrent(tx,f.scope(2)));return null;});
        assertEquals(before,f.store.snapshot());
    }

}
