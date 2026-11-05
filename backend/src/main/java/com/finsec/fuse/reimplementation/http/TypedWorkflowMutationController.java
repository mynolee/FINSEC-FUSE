package com.finsec.fuse.reimplementation.http;

import com.finsec.fuse.reimplementation.auth.LocalVirtualAdmissionContext;
import com.finsec.fuse.reimplementation.auth.LocalVirtualAccessPolicy;
import com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionService;
import com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanService;
import com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationService;
import com.finsec.fuse.reimplementation.simulation.SimulationFailure;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.simulation.VirtualGrantWorkflowBridge;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import static com.finsec.fuse.reimplementation.http.PreparedTypedActionCatalog.*;

/** Explicit prepared-action HTTP boundary; never auto-registers a bridge, payload or authority. */
@RestController
@RequestMapping("/api/v1/typed-actions")
public final class TypedWorkflowMutationController {
    @FunctionalInterface public interface CurrentCoordinates {
        /** Trusted server metadata only, no provider/command execution. Null means unconfigured/unavailable.
         * Must obtain actual current coordinates; echoing catalog coordinates is not freshness evidence.
         * Native service current/transaction checks remain mandatory even after this comparison.
         */
        Coordinates current(UUID commandRef,Purpose purpose,UUID requestId,
                LocalVirtualAdmissionContext.Admission admission,boolean reconciliation);
    }
    private final VirtualGrantWorkflowBridge bridge;
    private final PreparedTypedActionCatalog catalog;
    private final LocalVirtualAdmissionContext context;
    private final TypedWorkflowRequestDecoder decoder;
    private final CurrentCoordinates coordinates;
    private final PublicHttpErrors errors;
    public TypedWorkflowMutationController(VirtualGrantWorkflowBridge bridge,PreparedTypedActionCatalog catalog,
            LocalVirtualAdmissionContext context,TypedWorkflowRequestDecoder decoder,
            CurrentCoordinates coordinates,PublicHttpErrors errors) {
        this.bridge=Objects.requireNonNull(bridge);this.catalog=Objects.requireNonNull(catalog);
        this.context=Objects.requireNonNull(context);this.decoder=Objects.requireNonNull(decoder);
        this.coordinates=Objects.requireNonNull(coordinates);this.errors=Objects.requireNonNull(errors);
    }
    @PostMapping("/root-provisions")
    public ResponseEntity<Map<String,Object>> rootProvisions(HttpServletRequest request,@RequestBody byte[] body) {
        return invoke(request,body,Purpose.ROOT_PROVISION,false);
    }
    @PostMapping("/root-provisions/reconcile")
    public ResponseEntity<Map<String,Object>> rootProvisionsReconcile(HttpServletRequest request,@RequestBody byte[] body) {
        return invoke(request,body,Purpose.ROOT_PROVISION,true);
    }
    @PostMapping("/kyc-preparations")
    public ResponseEntity<Map<String,Object>> kycPreparations(HttpServletRequest request,@RequestBody byte[] body) {
        return invoke(request,body,Purpose.KYC_PREPARATION,false);
    }
    @PostMapping("/kyc-preparations/reconcile")
    public ResponseEntity<Map<String,Object>> kycPreparationsReconcile(HttpServletRequest request,@RequestBody byte[] body) {
        return invoke(request,body,Purpose.KYC_PREPARATION,true);
    }
    @PostMapping("/kyc-completions")
    public ResponseEntity<Map<String,Object>> kycCompletions(HttpServletRequest request,@RequestBody byte[] body) {
        return invoke(request,body,Purpose.KYC_COMPLETION,false);
    }
    @PostMapping("/kyc-completions/reconcile")
    public ResponseEntity<Map<String,Object>> kycCompletionsReconcile(HttpServletRequest request,@RequestBody byte[] body) {
        return invoke(request,body,Purpose.KYC_COMPLETION,true);
    }
    @PostMapping("/payment-reviews")
    public ResponseEntity<Map<String,Object>> paymentReviews(HttpServletRequest request,@RequestBody byte[] body) {
        return invoke(request,body,Purpose.PAYMENT_REVIEW,false);
    }
    @PostMapping("/payment-reviews/reconcile")
    public ResponseEntity<Map<String,Object>> paymentReviewsReconcile(HttpServletRequest request,@RequestBody byte[] body) {
        return invoke(request,body,Purpose.PAYMENT_REVIEW,true);
    }
    @PostMapping("/payment-reservations")
    public ResponseEntity<Map<String,Object>> paymentReservations(HttpServletRequest request,@RequestBody byte[] body) {
        return invoke(request,body,Purpose.PAYMENT_RESERVATION,false);
    }
    @PostMapping("/payment-reservations/reconcile")
    public ResponseEntity<Map<String,Object>> paymentReservationsReconcile(HttpServletRequest request,@RequestBody byte[] body) {
        return invoke(request,body,Purpose.PAYMENT_RESERVATION,true);
    }
    @PostMapping("/mock-payment-completions")
    public ResponseEntity<Map<String,Object>> mockPaymentCompletions(HttpServletRequest request,@RequestBody byte[] body) {
        return invoke(request,body,Purpose.MOCK_PAYMENT_COMPLETION,false);
    }
    @PostMapping("/mock-payment-completions/reconcile")
    public ResponseEntity<Map<String,Object>> mockPaymentCompletionsReconcile(HttpServletRequest request,@RequestBody byte[] body) {
        return invoke(request,body,Purpose.MOCK_PAYMENT_COMPLETION,true);
    }
    @PostMapping("/continuations")
    public ResponseEntity<Map<String,Object>> continuations(HttpServletRequest request,@RequestBody byte[] body) {
        return invoke(request,body,Purpose.CONTINUATION,false);
    }
    @PostMapping("/continuations/reconcile")
    public ResponseEntity<Map<String,Object>> continuationsReconcile(HttpServletRequest request,@RequestBody byte[] body) {
        return invoke(request,body,Purpose.CONTINUATION,true);
    }
    private ResponseEntity<Map<String,Object>> invoke(HttpServletRequest request,byte[] body,Purpose purpose,boolean reconciliation){
        try {
            var admission=LocalVirtualAuthenticationFilter.admission(request,context);
            var selected=decoder.decode(request,body);
            var current=coordinates.current(selected.commandRef(),purpose,selected.requestId(),admission,reconciliation);
            if(current==null)throw SimulationFailure.unavailable();
            var decision=admission.authorize(PreparedTypedActionCatalog.operation(purpose),current.workflowId(),current.customerId());
            if(decision==LocalVirtualAccessPolicy.Decision.SCOPE_UNCONFIRMED)throw SimulationFailure.unavailable();
            if(decision!=LocalVirtualAccessPolicy.Decision.ALLOW)throw SimulationFailure.forbidden();
            var action=catalog.resolveForAdmission(selected.commandRef(),purpose,selected.requestId(),admission,current);
            var caller=new Caller(admission.actor().actorId(),action.principal().issuerSubjectId());
            Map<String,Object> projected=switch(action.payload()){
                case Root p -> TypedWorkflowOutcomeProjection.project(action,reconciliation?bridge.reconcileRoot(caller,p.command()):bridge.startTyped(caller,p.command()));
                case Preparation p -> TypedWorkflowOutcomeProjection.project(action,reconciliation?bridge.reconcilePreparation(caller,p.command()):bridge.prepareKyc(caller,p.command()));
                case KycCompletion p -> TypedWorkflowOutcomeProjection.project(action,reconciliation?bridge.reconcileStage(caller,p.command()):bridge.completeAgentStage(caller,p.command(),p.result()));
                case Review p -> TypedWorkflowOutcomeProjection.project(action,reconciliation?bridge.reconcilePaymentReview(caller,p.command()):bridge.reviewPayment(caller,p.command()));
                case Reservation p -> TypedWorkflowOutcomeProjection.project(action,reconciliation?bridge.reconcilePaymentReservation(caller,p.command()):bridge.reservePayment(caller,p.command()));
                case Payment p -> TypedWorkflowOutcomeProjection.project(action,reconciliation?bridge.reconcilePayment(caller,p.command()):bridge.completeMockPayment(caller,p.command()));
                case Continuation p -> TypedWorkflowOutcomeProjection.project(action,reconciliation?bridge.reconcileContinuation(caller,p.command()):bridge.continueTyped(caller,p.command()));
            };
            int status=switch((String)projected.get("status")){
                case "VIRTUAL_COMMITTED_IN_PROCESS","VIRTUAL_REPLAYED_IN_PROCESS","REFUSED_BEFORE_ADMISSION" -> 200;
                case "IDENTITY_CONFLICT" -> 409;
                default -> 503;
            };
            return ResponseEntity.status(status).body(projected);
        }catch(PublicHttpErrors.Rejected rejected){return errors.response(rejected.error());}
        catch(LocalVirtualAdmissionContext.Failure failure){
            return errors.response(switch(failure.code()){
                case UNAUTHENTICATED -> PublicHttpErrors.Error.UNAUTHENTICATED;
                case FORBIDDEN -> PublicHttpErrors.Error.FORBIDDEN;
                case UNAVAILABLE -> PublicHttpErrors.Error.DEPENDENCY_UNAVAILABLE;
            });
        }catch(PreparedTypedActionCatalog.Failure failure){
            return errors.response(switch(failure.code()){
                case INVALID_REQUEST -> PublicHttpErrors.Error.INVALID_REQUEST;
                case FORBIDDEN -> PublicHttpErrors.Error.FORBIDDEN;
                case UNAUTHENTICATED -> PublicHttpErrors.Error.UNAUTHENTICATED;
                case UNKNOWN_REFERENCE,BINDING_UNCONFIRMED -> PublicHttpErrors.Error.DEPENDENCY_UNAVAILABLE;
            });
        }catch(SimulationFailure failure){return errors.response(PublicHttpErrors.forStatus(failure.status()));}
        catch(ActionJournal.ActionConflictException conflict){
            return ResponseEntity.status(409).body(Map.of("decision","ERROR","reasonCodes",java.util.List.of("IDENTITY_CONFLICT"),"message","IDENTITY_CONFLICT"));
        }
        catch(RuntimeException unavailable){return errors.response(PublicHttpErrors.Error.DEPENDENCY_UNAVAILABLE);}
    }
    private record Caller(String actorId,String subjectId) implements SyntheticRootProvisionService.RootServerContext,
            SyntheticMockPaymentPlanService.PlanServerContext,SyntheticTypedContinuationService.ContinuationServerContext { }
}
