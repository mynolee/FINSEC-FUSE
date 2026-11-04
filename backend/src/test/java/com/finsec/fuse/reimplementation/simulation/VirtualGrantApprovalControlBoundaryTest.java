package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.auth.SyntheticMockPaymentReceiptCodec;
import com.finsec.fuse.reimplementation.grant.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanService.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentTransactionBinding.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationFixture.*;
import static org.junit.jupiter.api.Assertions.*;

/** Actual virtual receipts/transactions over synthetic explicit facts, never actual payment authority. */
class VirtualGrantApprovalControlBoundaryTest {
    static UUID id(long n){return VirtualGrantWorkflowBridgeTest.id(n);}
    static final String APPROVALS="virtual_grant_profile_review_approvals",AI="virtual_grant_profile_approval_invalidations",
            PLANS="virtual_grant_profile_payment_plans",PI="virtual_grant_profile_payment_invalidations";
    static final class Scenario {
        final VirtualGrantPaymentIssuanceProofTest.Fixture f=new VirtualGrantPaymentIssuanceProofTest.Fixture();
        final SyntheticMockPaymentPlanService plans;
        final ReserveCommand reservation;
        Scenario(){
            var i=f.app.loan.identity();
            var evidence=new EvidenceSnapshot(id(2900),id(1600),id(1601),"c".repeat(64),"a".repeat(64),f.app.seed.f.source,
                    List.of(id(1999)),List.of(new SimulationSpec.Fact(id(1999),i.customerId(),SimulationSpec.Kind.ID_DOC,SimulationSpec.Outcome.PASS,true,Instant.ofEpochSecond(100),Instant.ofEpochSecond(400))));
            plans=new SyntheticMockPaymentPlanService(f.app.journal,new LocalPlanFacts(){
                public Gate current(PlanServerContext c,com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity identity,PlanOperation op,OwnedMockPaymentPlanPort.OwnedPlanTx tx){
                    return c.actorId().equals(f.reviewer.actorId())?Gate.CLEAR:Gate.REFUSED;}
                public ResolvedEvidence resolveEvidence(PlanServerContext c,com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity identity,ReviewBindings b,OwnedMockPaymentPlanPort.OwnedPlanTx tx){return new ResolvedEvidence(b,evidence);}
            });
            reservation=new ReserveCommand(f.identity(2802,f.child,"synthetic-reserve"),f.intended,f.approval.reviewSnapshotHash(),f.point);
        }
        VirtualWorkflowLane.Scope scope(){return new VirtualWorkflowLane.Scope(f.child.workflowId(),f.child.generation(),f.child.customerId());}
        Map<String,Object> workflow(){return f.app.workflow();}
        UUID hold(boolean source){var target=source?new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.SOURCE_VERSION,
                    Map.of("documentId",f.app.seed.f.source.documentId().toString(),"documentVersion",1)):
                    new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.RUN,Map.of("runId",id(1202).toString()));
            return UUID.fromString((String)f.app.seed.f.quarantines.create(ACTOR,f.app.seed.f.id(),target,"SYNTHETIC_CONTROL","").get("quarantineId"));}
        void release(UUID q){f.app.seed.f.quarantines.release(ACTOR,f.app.seed.f.id(),q,
                new VirtualQuarantineService.Remediation(DOCUMENT,2,List.of(ID_FACT),"synthetic checked",null,null));}
        void issueAndReserve(){assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,f.issue(f.proof()).status());
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,plans.reserve(f.reviewer,reservation).status());}
        void pay(){
            var d=f.intended;var i=f.identity(2803,f.child,"synthetic-payment-completion");var digest=new DigestBinding(i.canonicalBodyDigest(),"SHA-256",new byte[]{1,2,3});
            var input=new SyntheticMockPaymentReceiptCodec.Input(i.globalRequestId(),i.actorId(),i.operation(),i.canonicalizationVersion(),digest.algorithm(),digest.bytes(),
                    d.grantId(),d.actionId(),d.paymentId(),d.targetRunId(),d.approvalId(),d.reservationId(),d.workflowId(),d.generation(),d.customerId(),d.applicationId(),d.amountKrw(),d.payoutAccountId(),d.securityPolicyVersion(),"EXECUTE_MOCK_PAYMENT","COMMITTED","CONSUMED");
            var command=new PaymentCommand(new StageCommand(i,com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction.EXECUTE_MOCK_PAYMENT),digest,input);
            var service=new SyntheticMockPaymentTransactionService(f.app.journal,new PaymentFactResolver(){
                public Gate current(ServerContext c,PaymentCommand command,OwnedTx tx){return c.actorId().equals(i.actorId())?Gate.CLEAR:Gate.REFUSED;}
                public ResolvedPayment resolve(ServerContext c,PaymentCommand command,OwnedTx tx){assertEquals(d,tx.paymentDomain(d.reservationId()));return new ResolvedPayment(d,digest,input,List.of());}
            });
            var out=service.completePayment(f.app.seed.context,command);assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,out.status());
            assertNotNull(out.receipt());assertFalse(out.actualAuthority());assertFalse(out.durable());
        }
    }
    @Test void availableApprovalTombstoneSurvivesReleaseAndStateChallengeBeforeFreshReserve(){
        for(boolean source:List.of(true,false)){
            var s=new Scenario();assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,s.f.issue(s.f.proof()).status());
            var history=s.f.app.seed.f.store.snapshot().get(APPROVALS);UUID q=s.hold(source);
            var tomb=s.f.app.seed.f.store.snapshot().get(AI).get(s.f.approval.approvalId().toString());assertNotNull(tomb);
            s.release(q);assertEquals(tomb,s.f.app.seed.f.store.snapshot().get(AI).get(s.f.approval.approvalId().toString()));
            assertEquals(history,s.f.app.seed.f.store.snapshot().get(APPROVALS));
            // Adversarial in-memory state challenge isolates the permanent approval guard, not a public resume.
            s.f.app.seed.f.store.transaction(tx->{var w=new LinkedHashMap<>(tx.get("virtual_workflows",id(1).toString()));w.put("state","APPROVED");tx.put("virtual_workflows",id(1).toString(),w);return null;});
            var before=s.f.app.seed.f.store.snapshot();
            assertThrows(SimulationFailure.class,()->s.f.app.seed.f.store.transaction(tx->{VirtualGrantWorkflowControl.requireApprovalUsable(tx,s.scope(),s.f.approval.approvalId());return null;}));
            var out=s.plans.reserve(s.f.reviewer,s.reservation);assertNotEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,out.status());assertNull(out.receipt());assertEquals(before,s.f.app.seed.f.store.snapshot());
        }
    }
    @Test void reservedPlanAndApprovalBothRetainTombstonesAndImmutableHistoryAfterRelease(){
        var s=new Scenario();s.issueAndReserve();var before=s.f.app.seed.f.store.snapshot();UUID q=s.hold(true);
        var approvalTomb=s.f.app.seed.f.store.snapshot().get(AI).get(s.f.approval.approvalId().toString());
        var planTomb=s.f.app.seed.f.store.snapshot().get(PI).get(s.f.intended.reservationId().toString());assertNotNull(approvalTomb);assertNotNull(planTomb);
        s.release(q);var after=s.f.app.seed.f.store.snapshot();
        assertEquals(approvalTomb,after.get(AI).get(s.f.approval.approvalId().toString()));assertEquals(planTomb,after.get(PI).get(s.f.intended.reservationId().toString()));
        assertEquals(before.get(APPROVALS),after.get(APPROVALS));assertEquals(before.get(PLANS),after.get(PLANS));
        assertEquals(before.get("virtual_grant_profile_root_receipts"),after.get("virtual_grant_profile_root_receipts"));
    }
    @Test void coherentActualPaidGraphIsExcludedFromHoldMutationWithoutRelyingOnPaidLabel(){
        var s=new Scenario();s.issueAndReserve();s.pay();assertEquals("PAID",s.workflow().get("state"));
        var workflow=s.workflow();var before=s.f.app.seed.f.store.snapshot();s.hold(true);var after=s.f.app.seed.f.store.snapshot();
        assertEquals(workflow,s.workflow());assertEquals(before.get(PLANS),after.get(PLANS));assertEquals(before.get(APPROVALS),after.get(APPROVALS));
        assertFalse(after.getOrDefault(AI,Map.of()).containsKey(s.f.approval.approvalId().toString()));
        assertFalse(after.getOrDefault(PI,Map.of()).containsKey(s.f.intended.reservationId().toString()));
        assertEquals(0,s.f.app.seed.providers.get());
    }
}
