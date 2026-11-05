package com.finsec.fuse.reimplementation.http;

import com.finsec.fuse.reimplementation.grant.*;
import com.finsec.fuse.reimplementation.simulation.VirtualWorkflowLane;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.http.PreparedTypedActionCatalog.*;
import static com.finsec.fuse.reimplementation.http.PreparedTypedActionCatalogTest.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;

/** Public whitelist contract over supplied native outcomes, not actual committed service rows. */
final class TypedWorkflowOutcomeProjectionTest {
    private static final Set<String> COMMON=Set.of("schemaVersion","commandRef","purpose","requestId","workflowId","requestedGeneration",
        "status","effectKnowledge","replayed","executionMode","actualAuthority","durable","executionAuthorityGranted");
    private static final Set<String> METADATA=Set.of("schemaVersion","commandRef","purpose","requestId","workflowId","requestedGeneration",
        "customerId","executionMode","actualAuthority","durable","executionAuthorityGranted");
    private static final Set<Status> UNKNOWN=Set.of(Status.COMMIT_UNKNOWN,Status.RECONCILIATION_UNCONFIRMED,
        Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH,Status.TRANSACTION_INVARIANT_UNCONFIRMED);
    private boolean committed(Status status){return status==Status.VIRTUAL_COMMITTED_IN_PROCESS||status==Status.VIRTUAL_REPLAYED_IN_PROCESS;}
    private SyntheticMockPaymentPlanBinding.ApprovalSnapshot approval(NativeFixture f,boolean reserved){
        var material=new SyntheticMockPaymentPlanBinding.ReviewMaterial(new VirtualWorkflowLane.Scope(id(1),1,CUSTOMER),id(613),1000,id(21),
            id(7010),id(7011),H,H,f.source.documentId(),1,f.source.contentHash(),POLICY,0,0,20);
        return new SyntheticMockPaymentPlanBinding.ApprovalSnapshot(f.review.approvalId(),f.review.identity().globalRequestId(),ALIAS,
            f.review.decision(),material,H,NOW,NOW.plusSeconds(60),0,20,reserved?
                SyntheticMockPaymentPlanBinding.ApprovalPlanState.RESERVED:SyntheticMockPaymentPlanBinding.ApprovalPlanState.AVAILABLE);
    }
    private Map<String,Object> project(NativeFixture f,PreparedAction a,Status status){
        boolean commit=committed(status);boolean unknown=UNKNOWN.contains(status);
        return switch(a.purpose()){
            case ROOT_PROVISION -> TypedWorkflowOutcomeProjection.project(a,new SyntheticRootProvisionBinding.RootOutcome(status,
                commit?new SyntheticRootProvisionBinding.RootReceipt(1,f.root):null,
                commit?SyntheticRootProvisionBinding.RootEffect.COMMITTED_IN_PROCESS:unknown?SyntheticRootProvisionBinding.RootEffect.UNKNOWN:
                    SyntheticRootProvisionBinding.RootEffect.NO_NEW_ROOT_PROVISION_ATTEMPT_THIS_INVOCATION));
            case KYC_PREPARATION -> TypedWorkflowOutcomeProjection.project(a,new SyntheticKycPreparationBinding.PreparationOutcome(status,
                commit?new SyntheticKycPreparationBinding.PreparationReceipt(f.preparation.identity(),SyntheticKycPreparationBinding.descriptor(f.preparation),H,
                    SyntheticKycPreparationBinding.Decision.PREPARED,SyntheticKycPreparationBinding.Refusal.NONE,1,1,1):null,
                commit?SyntheticKycPreparationBinding.PreparationEffect.COMMITTED_IN_PROCESS:unknown?SyntheticKycPreparationBinding.PreparationEffect.UNKNOWN:
                    SyntheticKycPreparationBinding.PreparationEffect.NO_NEW_PREPARATION_ATTEMPT_THIS_INVOCATION));
            case KYC_COMPLETION,MOCK_PAYMENT_COMPLETION -> {
                var result=a.purpose()==Purpose.KYC_COMPLETION?f.result:new OutsidePreparedResult(f.payment.expectedReceipt().paymentId(),
                    com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.BusinessConclusion.POSITIVE,CANARY,new byte[]{99},new byte[]{98});
                yield TypedWorkflowOutcomeProjection.project(a,new StageOutcome(status,commit?new Receipt(a.identity(),ReceiptKind.CONSUMPTION,result,null):null,
                    commit?EffectKnowledge.COMMITTED_IN_PROCESS:unknown?EffectKnowledge.UNKNOWN:EffectKnowledge.NO_NEW_CONSUMPTION_ATTEMPT_THIS_INVOCATION));
            }
            case PAYMENT_REVIEW,PAYMENT_RESERVATION -> {
                boolean reserve=a.purpose()==Purpose.PAYMENT_RESERVATION;
                yield TypedWorkflowOutcomeProjection.project(a,new SyntheticMockPaymentPlanBinding.PlanOutcome(status,
                    commit?new SyntheticMockPaymentPlanBinding.PlanReceipt(1,reserve?SyntheticMockPaymentPlanBinding.PlanOperation.RESERVE:
                        SyntheticMockPaymentPlanBinding.PlanOperation.REVIEW,a.identity(),approval(f,reserve),reserve?f.reserve.domain():null,reserve?1:0):null,
                    commit?SyntheticMockPaymentPlanBinding.PlanEffect.COMMITTED_IN_PROCESS:unknown?SyntheticMockPaymentPlanBinding.PlanEffect.UNKNOWN:
                        SyntheticMockPaymentPlanBinding.PlanEffect.NO_NEW_PLAN_ATTEMPT_THIS_INVOCATION));
            }
            case CONTINUATION -> TypedWorkflowOutcomeProjection.project(a,new SyntheticTypedContinuationBinding.ContinuationOutcome(status,
                commit?new SyntheticTypedContinuationBinding.ContinuationReceipt(1,SyntheticTypedContinuationBinding.ContinuationKind.ADVANCED,f.continuation):null,
                commit?SyntheticTypedContinuationBinding.ContinuationEffect.COMMITTED_IN_PROCESS:unknown?SyntheticTypedContinuationBinding.ContinuationEffect.UNKNOWN:
                    SyntheticTypedContinuationBinding.ContinuationEffect.NO_NEW_CONTINUATION_ATTEMPT_THIS_INVOCATION));
        };
    }
    private Set<String> receiptKeys(Purpose purpose){
        var keys=new HashSet<>(Set.of("kind","grantId","actionId","targetRunId"));
        switch(purpose){
            case ROOT_PROVISION -> {}
            case KYC_PREPARATION -> keys.addAll(Set.of("decision","refusal"));
            case KYC_COMPLETION -> keys.add("resultId");
            case PAYMENT_REVIEW -> keys.addAll(Set.of("approvalId","decision"));
            case PAYMENT_RESERVATION -> keys.addAll(Set.of("approvalId","decision","reservationId","paymentId"));
            case MOCK_PAYMENT_COMPLETION -> keys.addAll(Set.of("resultId","paymentId","approvalId","reservationId"));
            case CONTINUATION -> keys.addAll(Set.of("continuationKind","committedGeneration"));
        }
        return keys;
    }
    private void noSecretOrAuthority(Map<String,Object> result){
        assertEquals("VIRTUAL_SIMULATION",result.get("executionMode"));assertEquals(false,result.get("actualAuthority"));
        assertEquals(false,result.get("durable"));assertEquals(false,result.get("executionAuthorityGranted"));
        String visible=result.toString();assertFalse(visible.contains(CANARY));assertFalse(visible.contains("HMAC"));
        assertFalse(visible.contains("bindingBytes"));assertFalse(visible.contains("subject"));assertFalse(visible.contains("sourceContentHash"));
    }
    @Test void metadataHasOnlyIndependentPublicWhitelistAndNeverPreparedMaterial(){
        var f=new NativeFixture();var catalog=new PreparedTypedActionCatalog(f.actions,7);
        for(var a:f.actions){var projected=TypedWorkflowOutcomeProjection.metadata(catalog.metadata(a.commandRef()));
            assertEquals(METADATA,projected.keySet());assertEquals(a.commandRef().toString(),projected.get("commandRef"));
            assertEquals(CUSTOMER,projected.get("customerId"));noSecretOrAuthority(projected);
            assertThrows(UnsupportedOperationException.class,()->projected.put("extra",CANARY));}
    }
    @Test void everyNativeStatusAcrossSevenPayloadsPreservesKnowledgeAndNeverInventsReceipt(){
        var f=new NativeFixture();int combinations=0;
        for(var a:f.actions)for(var status:Status.values()){
            var out=project(f,a,status);var keys=new HashSet<>(COMMON);if(committed(status))keys.add("receipt");
            assertEquals(keys,out.keySet());assertEquals(status.name(),out.get("status"));
            assertEquals(status==Status.VIRTUAL_REPLAYED_IN_PROCESS,out.get("replayed"));
            assertEquals(a.identity().globalRequestId().toString(),out.get("requestId"));
            assertEquals(a.identity().generation(),out.get("requestedGeneration"));noSecretOrAuthority(out);
            if(committed(status)){
                var receipt=(Map<?,?>)out.get("receipt");assertEquals(receiptKeys(a.purpose()),receipt.keySet());
                assertEquals(a.identity().grantId().toString(),receipt.get("grantId"));
                assertThrows(UnsupportedOperationException.class,receipt::clear);
                assertEquals("COMMITTED_IN_PROCESS",out.get("effectKnowledge"));
            }else{assertFalse(out.containsKey("receipt"));if(UNKNOWN.contains(status))assertEquals("UNKNOWN",out.get("effectKnowledge"));}
            combinations++;
        }
        assertEquals(7*Status.values().length,combinations);
    }
    @Test void continuationDeniedProjectsOldCommittedGenerationWithoutRelabelingRequestedGeneration(){
        var f=new NativeFixture();var action=f.actions.get(6);
        var outcome=new SyntheticTypedContinuationBinding.ContinuationOutcome(Status.VIRTUAL_COMMITTED_IN_PROCESS,
            new SyntheticTypedContinuationBinding.ContinuationReceipt(1,SyntheticTypedContinuationBinding.ContinuationKind.DENIED,f.continuation),
            SyntheticTypedContinuationBinding.ContinuationEffect.COMMITTED_IN_PROCESS);
        var out=TypedWorkflowOutcomeProjection.project(action,outcome);var receipt=(Map<?,?>)out.get("receipt");
        assertEquals(2,out.get("requestedGeneration"));assertEquals(1,receipt.get("committedGeneration"));
        assertEquals("DENIED",receipt.get("continuationKind"));noSecretOrAuthority(out);
    }
    @Test void mismatchedNativeReceiptAndUnmappedLoanRefusalFailWithFixedError(){
        var f=new NativeFixture();var action=f.actions.get(2);
        assertNotNull(project(f,action,Status.VIRTUAL_COMMITTED_IN_PROCESS));
        var different=new Receipt(identity(999,1,301),ReceiptKind.CONSUMPTION,f.result,null);
        var bad=new StageOutcome(Status.VIRTUAL_COMMITTED_IN_PROCESS,different,EffectKnowledge.COMMITTED_IN_PROCESS);
        var error=assertThrows(IllegalArgumentException.class,()->TypedWorkflowOutcomeProjection.project(action,bad));
        assertEquals("INVALID_TYPED_OUTCOME_BINDING",error.getMessage());
        var refused=new StageOutcome(Status.REFUSED_BEFORE_ADMISSION,null,EffectKnowledge.NO_NEW_CONSUMPTION_ATTEMPT_THIS_INVOCATION,
            new EvaluationRefusal(1,f.stage.identity(),id(778)));
        assertThrows(IllegalArgumentException.class,()->TypedWorkflowOutcomeProjection.project(action,refused));
        var wrongResult=new OutsidePreparedResult(id(9999),f.result.businessConclusion(),f.result.bindingProfile(),f.result.bindingBytes(),f.result.bindingDigest());
        assertThrows(IllegalArgumentException.class,()->TypedWorkflowOutcomeProjection.project(action,
            new StageOutcome(Status.VIRTUAL_COMMITTED_IN_PROCESS,new Receipt(action.identity(),ReceiptKind.CONSUMPTION,wrongResult,null),EffectKnowledge.COMMITTED_IN_PROCESS)));
    }
    @Test void originalReviewAvailableAndReserveReservedReceiptsAreNotRelabeledConsumed(){
        var f=new NativeFixture();assertNotNull(project(f,f.actions.get(3),Status.VIRTUAL_COMMITTED_IN_PROCESS));
        var available=approval(f,false);
        var consumed=new SyntheticMockPaymentPlanBinding.ApprovalSnapshot(available.approvalId(),available.reviewRequestId(),available.reviewerActorId(),
            available.decision(),available.material(),available.reviewSnapshotHash(),available.createdAt(),available.expiresAt(),available.extraRiskLimit(),available.riskLimit(),
            SyntheticMockPaymentPlanBinding.ApprovalPlanState.CONSUMED);
        var wrong=new SyntheticMockPaymentPlanBinding.PlanReceipt(1,SyntheticMockPaymentPlanBinding.PlanOperation.REVIEW,f.review.identity(),consumed,null,0);
        assertThrows(IllegalArgumentException.class,()->TypedWorkflowOutcomeProjection.project(f.actions.get(3),
            new SyntheticMockPaymentPlanBinding.PlanOutcome(Status.VIRTUAL_COMMITTED_IN_PROCESS,wrong,SyntheticMockPaymentPlanBinding.PlanEffect.COMMITTED_IN_PROCESS)));
    }
    @Test void nullWrongPurposeAndRootReceiptIdentityCannotBecomePublicSuccess(){
        var f=new NativeFixture();var rootAction=f.actions.get(0);
        assertNotNull(project(f,rootAction,Status.VIRTUAL_COMMITTED_IN_PROCESS));
        assertThrows(IllegalArgumentException.class,()->TypedWorkflowOutcomeProjection.metadata(null));
        assertThrows(IllegalArgumentException.class,()->TypedWorkflowOutcomeProjection.project(rootAction,(SyntheticRootProvisionBinding.RootOutcome)null));
        var alternate=new SyntheticRootProvisionBinding.RootCommand(identity(999,1,101),f.root.inputs(),f.root.workflowPlan());
        var wrong=new SyntheticRootProvisionBinding.RootOutcome(Status.VIRTUAL_COMMITTED_IN_PROCESS,
            new SyntheticRootProvisionBinding.RootReceipt(1,alternate),SyntheticRootProvisionBinding.RootEffect.COMMITTED_IN_PROCESS);
        var error=assertThrows(IllegalArgumentException.class,()->TypedWorkflowOutcomeProjection.project(rootAction,wrong));
        assertEquals("INVALID_TYPED_OUTCOME_BINDING",error.getMessage());
        assertThrows(IllegalArgumentException.class,()->TypedWorkflowOutcomeProjection.project(f.actions.get(1),wrong));
    }

}
