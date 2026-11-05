package com.finsec.fuse.reimplementation.http;

import com.finsec.fuse.reimplementation.auth.LocalVirtualAdmissionContext;
import com.finsec.fuse.reimplementation.auth.LocalVirtualAccessPolicy;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.grant.*;
import com.finsec.fuse.reimplementation.simulation.SimulationAccess.Operation;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Immutable server-prepared commands. A selector or matching snapshot is not transaction/issuer authority. */
public final class PreparedTypedActionCatalog {
    public enum Purpose { ROOT_PROVISION, KYC_PREPARATION, KYC_COMPLETION, PAYMENT_REVIEW,
        PAYMENT_RESERVATION, MOCK_PAYMENT_COMPLETION, CONTINUATION }
    public enum Code { INVALID_REQUEST, UNKNOWN_REFERENCE, BINDING_UNCONFIRMED, FORBIDDEN, UNAUTHENTICATED }
    public static final class Failure extends RuntimeException {
        private final Code code;
        private Failure(Code code){super(code.name(),null,false,false);this.code=code;}
        public Code code(){return code;}
    }
    public record PrincipalBinding(UUID localPrincipalId,long bindingRevision,String actorAlias,String issuerSubjectId){
        public PrincipalBinding {if(localPrincipalId==null||bindingRevision<0)throw invalid();SimulationSpec.synthetic(actorAlias);text(issuerSubjectId);}
        @Override public String toString(){return "PreparedPrincipalSubjectBinding[REDACTED]";}
    }
    public record Coordinates(UUID workflowId,int generation,String customerId,UUID documentId,int documentVersion,
            String sourceContentHash,String policyVersion){
        public Coordinates {
            if(workflowId==null||generation<1||documentId==null||documentVersion<1||!SimulationSpec.hash(sourceContentHash))throw invalid();
            SimulationSpec.synthetic(customerId);text(policyVersion);
        }
    }
    public sealed interface Payload permits Root,Preparation,KycCompletion,Review,Reservation,Payment,Continuation {
        Purpose purpose(); CommandIdentity identity();
    }
    public record Root(SyntheticRootProvisionBinding.RootCommand command) implements Payload {
        public Root {required(command);}
        public Purpose purpose(){return Purpose.ROOT_PROVISION;}
        public CommandIdentity identity(){return command.identity();}
        @Override public String toString(){return "PreparedRootAction[REDACTED]";}
    }
    public record Preparation(SyntheticKycPreparationBinding.PreparationCommand command) implements Payload {
        public Preparation {required(command);}
        public Purpose purpose(){return Purpose.KYC_PREPARATION;}
        public CommandIdentity identity(){return command.identity();}
        @Override public String toString(){return "PreparedKycPreparation[REDACTED]";}
    }
    public record KycCompletion(OwnedGrantTransactionPort.StageCommand command,
            OwnedGrantTransactionPort.OutsidePreparedResult result) implements Payload {
        public KycCompletion {required(command);required(result);if(command.action()!=AllowedAction.EVALUATE_KYC)throw invalid();}
        public Purpose purpose(){return Purpose.KYC_COMPLETION;}
        public CommandIdentity identity(){return command.identity();}
        @Override public String toString(){return "PreparedKycCompletion[REDACTED]";}
    }
    public record Review(SyntheticMockPaymentPlanBinding.ReviewCommand command) implements Payload {
        public Review {required(command);}
        public Purpose purpose(){return Purpose.PAYMENT_REVIEW;}
        public CommandIdentity identity(){return command.identity();}
        @Override public String toString(){return "PreparedPaymentReview[REDACTED]";}
    }
    public record Reservation(SyntheticMockPaymentPlanBinding.ReserveCommand command) implements Payload {
        public Reservation {required(command);}
        public Purpose purpose(){return Purpose.PAYMENT_RESERVATION;}
        public CommandIdentity identity(){return command.identity();}
        @Override public String toString(){return "PreparedPaymentReservation[REDACTED]";}
    }
    public record Payment(SyntheticMockPaymentTransactionBinding.PaymentCommand command) implements Payload {
        public Payment {required(command);if(command.stage().action()!=AllowedAction.EXECUTE_MOCK_PAYMENT)throw invalid();}
        public Purpose purpose(){return Purpose.MOCK_PAYMENT_COMPLETION;}
        public CommandIdentity identity(){return command.stage().identity();}
        @Override public String toString(){return "PreparedMockPayment[REDACTED]";}
    }
    public record Continuation(SyntheticTypedContinuationBinding.ContinuationCommand command) implements Payload {
        public Continuation {required(command);}
        public Purpose purpose(){return Purpose.CONTINUATION;}
        public CommandIdentity identity(){return command.identity();}
        @Override public String toString(){return "PreparedContinuation[REDACTED]";}
    }
    /** Server object, never a request DTO or a response to serialize directly. */
    public record PreparedAction(UUID commandRef,Payload payload,PrincipalBinding principal,Coordinates coordinates){
        public PreparedAction {
            required(commandRef);required(payload);required(principal);required(coordinates);
            var id=payload.identity();
            if(!principal.actorAlias().equals(id.actorId())||!coordinates.workflowId().equals(id.workflowId())
                    ||coordinates.generation()!=id.generation()||!coordinates.customerId().equals(id.customerId()))throw invalid();
            if(payload instanceof Root root)source(coordinates,root.command().workflowPlan().application().source(),root.command().workflowPlan().riskTerms().policyVersion());
            if(payload instanceof Preparation prep)source(coordinates,prep.command().source(),prep.command().terms().policyVersion());
            if(payload instanceof Continuation next)source(coordinates,next.command().application().source(),next.command().originalTerms().policyVersion());
            if(payload instanceof Reservation reserve&&!coordinates.policyVersion().equals(reserve.command().domain().securityPolicyVersion()))throw invalid();
            if(payload instanceof Payment pay){
                var receipt=pay.command().expectedReceipt();
                if(!id.globalRequestId().equals(receipt.globalRequestId())||!id.actorId().equals(receipt.authenticatedActor())
                        ||!id.operation().equals(receipt.operation())||!id.canonicalizationVersion().equals(receipt.canonicalizationVersion())
                        ||!id.canonicalBodyDigest().equals(pay.command().admittedCommandDigest().identityDigestReference())
                        ||!pay.command().admittedCommandDigest().algorithm().equals(receipt.canonicalBodyDigestAlgorithm())
                        ||!java.util.Arrays.equals(pay.command().admittedCommandDigest().bytes(),receipt.canonicalBodyDigest())
                        ||!id.grantId().equals(receipt.grantId())||!id.actionId().equals(receipt.actionId())
                        ||!id.targetRunId().equals(receipt.targetRunId())||!id.workflowId().equals(receipt.workflowId())
                        ||id.generation()!=receipt.generation()||!id.customerId().equals(receipt.customerId())
                        ||!coordinates.policyVersion().equals(receipt.securityPolicyVersion()))throw invalid();
                // Digest bytes/algorithm are opaque typed bindings; their actual validation belongs to the payment service.
            }
        }
        public Purpose purpose(){return payload.purpose();}
        public CommandIdentity identity(){return payload.identity();}
        @Override public String toString(){return "PreparedTypedAction[REDACTED]";}
    }
    public record Metadata(UUID commandRef,Purpose purpose,UUID globalRequestId,Coordinates coordinates) {
        public Metadata {required(commandRef);required(purpose);required(globalRequestId);required(coordinates);}
    }
    private final Map<UUID,PreparedAction> actions;
    public PreparedTypedActionCatalog(List<PreparedAction> supplied,int maximumEntries){
        if(supplied==null||maximumEntries<1)throw invalid();
        try{supplied=List.copyOf(supplied);}catch(RuntimeException malformed){throw invalid();}
        if(supplied.size()>maximumEntries)throw invalid();
        var map=new LinkedHashMap<UUID,PreparedAction>();var requests=new java.util.HashSet<UUID>();
        for(var action:supplied){
            if(map.putIfAbsent(action.commandRef(),action)!=null||!requests.add(action.identity().globalRequestId()))throw invalid();
        }
        actions=Map.copyOf(map);
    }
    public int size(){return actions.size();}
    public Metadata metadata(UUID commandRef){
        var action=find(commandRef);return new Metadata(action.commandRef(),action.purpose(),action.identity().globalRequestId(),action.coordinates());
    }
    /** Only a live authenticated server admission may resolve the full prepared material. */
    public PreparedAction resolveForAdmission(UUID commandRef,Purpose purpose,UUID globalRequestId,
            LocalVirtualAdmissionContext.Admission admission,Coordinates expectedCoordinates){
        if(purpose==null||globalRequestId==null||expectedCoordinates==null)throw invalid();
        var action=find(commandRef);
        if(action.purpose()!=purpose||!action.identity().globalRequestId().equals(globalRequestId))throw fail(Code.INVALID_REQUEST);
        if(admission==null)throw fail(Code.UNAUTHENTICATED);
        var principal=admission.principal();var binding=action.principal();
        if(!principal.principalId().equals(binding.localPrincipalId())||principal.bindingRevision()!=binding.bindingRevision()
                ||!principal.actorAlias().equals(binding.actorAlias()))throw fail(Code.FORBIDDEN);
        if(!action.coordinates().equals(expectedCoordinates))throw fail(Code.BINDING_UNCONFIRMED);
        var decision=admission.authorize(operation(purpose),action.coordinates().workflowId(),action.coordinates().customerId());
        if(decision==LocalVirtualAccessPolicy.Decision.SCOPE_UNCONFIRMED)throw fail(Code.BINDING_UNCONFIRMED);
        if(decision!=LocalVirtualAccessPolicy.Decision.ALLOW)throw fail(Code.FORBIDDEN);
        return action;
    }
    public static Operation operation(Purpose purpose){
        if(purpose==null)throw invalid();
        return switch(purpose){
            case ROOT_PROVISION -> Operation.START;
            case KYC_PREPARATION,KYC_COMPLETION -> Operation.KYC_OBSERVATION;
            case PAYMENT_REVIEW -> Operation.REVIEW;
            case PAYMENT_RESERVATION,MOCK_PAYMENT_COMPLETION -> Operation.PAYMENT;
            case CONTINUATION -> Operation.RESUME;
        };
    }
    private PreparedAction find(UUID reference){if(reference==null)throw invalid();var action=actions.get(reference);if(action==null)throw fail(Code.UNKNOWN_REFERENCE);return action;}
    private static void source(Coordinates c,SimulationSpec.Source source,String policy){
        if(!c.documentId().equals(source.documentId())||c.documentVersion()!=source.documentVersion()
                ||!c.sourceContentHash().equals(source.contentHash())||!c.policyVersion().equals(policy))throw invalid();
    }
    private static void text(String value){if(value==null||value.isBlank()||value.length()>256)throw invalid();}
    private static void required(Object value){if(value==null)throw invalid();}
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("INVALID_PREPARED_TYPED_ACTION");}
    private static Failure fail(Code code){return new Failure(code);}
    @Override public String toString(){return "PreparedTypedActionCatalog[REDACTED]";}
}
