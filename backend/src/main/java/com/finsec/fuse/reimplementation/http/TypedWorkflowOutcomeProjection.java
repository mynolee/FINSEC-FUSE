package com.finsec.fuse.reimplementation.http;

import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.grant.*;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import java.util.LinkedHashMap;
import java.util.Map;
import static com.finsec.fuse.reimplementation.http.PreparedTypedActionCatalog.*;

/** Finite safe metadata projection of supplied typed service outcomes, never commit or authority proof. */
public final class TypedWorkflowOutcomeProjection {
    private TypedWorkflowOutcomeProjection() {}
    public static Map<String,Object> metadata(Metadata metadata){
        if(metadata==null)throw invalid();var c=metadata.coordinates();
        return freeze(object("schemaVersion",1,"commandRef",metadata.commandRef().toString(),"purpose",metadata.purpose().name(),
                "requestId",metadata.globalRequestId().toString(),"workflowId",c.workflowId().toString(),
                "requestedGeneration",c.generation(),"customerId",c.customerId(),"executionMode","VIRTUAL_SIMULATION",
                "actualAuthority",false,"durable",false,"executionAuthorityGranted",false));
    }
    public static Map<String,Object> project(PreparedAction action,SyntheticRootProvisionBinding.RootOutcome outcome){
        if(action==null||!(action.payload() instanceof Root payload)||outcome==null)throw invalid();
        var out=base(action,outcome.status(),outcome.effectKnowledge().name());
        if(outcome.receipt()!=null){
            if(!outcome.receipt().matches(payload.command()))throw invalid();
            out.put("receipt",receipt(action,"ROOT_PROVISION"));
        }
        return freeze(out);
    }
    public static Map<String,Object> project(PreparedAction action,SyntheticKycPreparationBinding.PreparationOutcome outcome){
        if(action==null||!(action.payload() instanceof Preparation payload)||outcome==null)throw invalid();
        var out=base(action,outcome.status(),outcome.effect().name());
        if(outcome.receipt()!=null){
            var r=outcome.receipt();identity(action,r.identity());
            if(!r.descriptor().equals(SyntheticKycPreparationBinding.descriptor(payload.command())))throw invalid();
            var safe=receipt(action,"KYC_PREPARATION");safe.put("decision",r.decision().name());safe.put("refusal",r.refusal().name());
            out.put("receipt",safe);
        }
        return freeze(out);
    }
    public static Map<String,Object> project(PreparedAction action,OwnedGrantTransactionPort.StageOutcome outcome){
        if(action==null||outcome==null||!(action.payload() instanceof KycCompletion||action.payload() instanceof Payment))throw invalid();
        // Standalone LOAN and its nonconsuming refusal have no admitted HTTP purpose here.
        if(outcome.evaluationRefusal()!=null)throw invalid();
        var out=base(action,outcome.status(),outcome.effectKnowledge().name());
        if(outcome.receipt()!=null){
            var r=outcome.receipt();identity(action,r.identity());
            if(r.kind()!=OwnedGrantTransactionPort.ReceiptKind.CONSUMPTION||r.result()==null)throw invalid();
            if(action.payload() instanceof KycCompletion kyc&&!r.result().equals(kyc.result()))throw invalid();
            if(action.payload() instanceof Payment pay&&!r.result().resultId().equals(pay.command().expectedReceipt().paymentId()))throw invalid();
            var safe=receipt(action,"CONSUMPTION");safe.put("resultId",r.result().resultId().toString());
            if(action.payload() instanceof Payment pay){
                safe.put("paymentId",pay.command().expectedReceipt().paymentId().toString());
                safe.put("approvalId",pay.command().expectedReceipt().approvalId().toString());
                safe.put("reservationId",pay.command().expectedReceipt().reservationId().toString());
            }
            out.put("receipt",safe);
        }
        return freeze(out);
    }
    public static Map<String,Object> project(PreparedAction action,SyntheticMockPaymentPlanBinding.PlanOutcome outcome){
        if(action==null||outcome==null||!(action.payload() instanceof Review||action.payload() instanceof Reservation))throw invalid();
        var out=base(action,outcome.status(),outcome.effectKnowledge().name());
        if(outcome.receipt()!=null){
            var r=outcome.receipt();identity(action,r.identity());var a=r.approval();var c=action.coordinates();var m=a.material();
            if(!m.scope().workflowId().equals(c.workflowId())||m.scope().generation()!=c.generation()||!m.scope().customerId().equals(c.customerId())
                    ||!m.documentId().equals(c.documentId())||m.documentVersion()!=c.documentVersion()
                    ||!m.sourceContentHash().equals(c.sourceContentHash())||!m.policyVersion().equals(c.policyVersion()))throw invalid();
            if(action.payload() instanceof Review review){
                var command=review.command();
                if(r.purpose()!=SyntheticMockPaymentPlanBinding.PlanOperation.REVIEW||!a.approvalId().equals(command.approvalId())
                        ||!a.reviewRequestId().equals(command.identity().globalRequestId())||!a.reviewerActorId().equals(command.identity().actorId())
                        ||a.decision()!=command.decision()||!a.reviewSnapshotHash().equals(command.expectedReviewSnapshotHash())
                        ||!a.createdAt().equals(command.now())||!a.expiresAt().equals(command.expiresAt())
                        ||a.state()!=(command.decision()==SyntheticMockPaymentPlanBinding.ReviewDecision.APPROVE
                            ?SyntheticMockPaymentPlanBinding.ApprovalPlanState.AVAILABLE:SyntheticMockPaymentPlanBinding.ApprovalPlanState.REJECTED))throw invalid();
            }else if(action.payload() instanceof Reservation reserve){
                var command=reserve.command();
                if(r.purpose()!=SyntheticMockPaymentPlanBinding.PlanOperation.RESERVE||!command.domain().equals(r.domain())
                        ||!a.approvalId().equals(command.domain().approvalId())||!a.reviewSnapshotHash().equals(command.expectedReviewSnapshotHash())
                        ||a.state()!=SyntheticMockPaymentPlanBinding.ApprovalPlanState.RESERVED)throw invalid();
            }
            var safe=receipt(action,r.purpose().name());safe.put("approvalId",a.approvalId().toString());safe.put("decision",a.decision().name());
            if(r.domain()!=null){safe.put("reservationId",r.domain().reservationId().toString());safe.put("paymentId",r.domain().paymentId().toString());}
            out.put("receipt",safe);
        }
        return freeze(out);
    }
    public static Map<String,Object> project(PreparedAction action,SyntheticTypedContinuationBinding.ContinuationOutcome outcome){
        if(action==null||!(action.payload() instanceof Continuation payload)||outcome==null)throw invalid();
        var out=base(action,outcome.status(),outcome.effectKnowledge().name());
        if(outcome.receipt()!=null){
            var r=outcome.receipt();if(!r.matches(payload.command()))throw invalid();
            var safe=receipt(action,"CONTINUATION");safe.put("continuationKind",r.kind().name());
            safe.put("committedGeneration",r.committedGeneration());out.put("receipt",safe);
        }
        return freeze(out);
    }
    private static Map<String,Object> base(PreparedAction action,OwnedGrantTransactionPort.Status status,String effect){
        return object("schemaVersion",1,"commandRef",action.commandRef().toString(),"purpose",action.purpose().name(),
                "requestId",action.identity().globalRequestId().toString(),"workflowId",action.identity().workflowId().toString(),
                "requestedGeneration",action.identity().generation(),"status",status.name(),"effectKnowledge",effect,
                "replayed",status==OwnedGrantTransactionPort.Status.VIRTUAL_REPLAYED_IN_PROCESS,"executionMode","VIRTUAL_SIMULATION",
                "actualAuthority",false,"durable",false,"executionAuthorityGranted",false);
    }
    private static Map<String,Object> receipt(PreparedAction action,String kind){
        return object("kind",kind,"grantId",action.identity().grantId().toString(),"actionId",action.identity().actionId().toString(),
                "targetRunId",action.identity().targetRunId().toString());
    }
    private static void identity(PreparedAction action,CommandIdentity identity){if(!action.identity().equals(identity))throw invalid();}
    private static Map<String,Object> object(Object... pairs){var out=new LinkedHashMap<String,Object>();for(int i=0;i<pairs.length;i+=2)out.put((String)pairs[i],pairs[i+1]);return out;}
    private static Map<String,Object> freeze(Map<String,Object> map){return CanonicalJson.immutableObject(map);}
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("INVALID_TYPED_OUTCOME_BINDING");}
}
