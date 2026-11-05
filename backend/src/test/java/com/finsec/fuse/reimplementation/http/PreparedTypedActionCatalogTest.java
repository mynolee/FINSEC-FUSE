package com.finsec.fuse.reimplementation.http;

import com.finsec.fuse.reimplementation.auth.*;
import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.grant.*;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.simulation.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.http.PreparedTypedActionCatalog.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;

/** Explicit native synthetic records and canonical registry evidence; no service transaction or HTTP execution. */
final class PreparedTypedActionCatalogTest {
    static UUID id(long n){return new UUID(91,n);}
    static final String ALIAS="synthetic-typed-actor",CUSTOMER="synthetic-typed-customer",POLICY="synthetic-policy";
    static final String CANARY="SYNTHETIC_PRIVATE_FRAME_SUBJECT_SOURCE";
    static final String H="a".repeat(64);
    static final Instant NOW=Instant.ofEpochSecond(150);
    static CommandIdentity identity(long request,int gen,long base){
        return new CommandIdentity(ALIAS,id(request),"synthetic-prepared-phase","synthetic-canonical-v1",H,
            id(base),id(base+1),id(base+2),id(1),gen,CUSTOMER);
    }
    static final class NativeFixture {
        final SimulationSpec.Source source=new SimulationSpec.Source(id(20),1,CANARY,SimulationSpec.rawHash(CANARY),true);
        final SimulationSpec.Application application=new SimulationSpec.Application("synthetic-fixture","synthetic-business",CUSTOMER,
            1000,id(21),2000,3000,true,source);
        final SimulationSpec.RiskTerms terms=new SimulationSpec.RiskTerms(POLICY,1,1,1,20,5,1,Duration.ofSeconds(60));
        final Map<AllowedAction,SyntheticRootProvisionBinding.AgentReference> agents=Map.of(AllowedAction.EVALUATE_KYC,
            new SyntheticRootProvisionBinding.AgentReference("synthetic-target",1));
        final PrincipalBinding binding=new PrincipalBinding(id(90),0,ALIAS,CANARY);
        final SyntheticRootProvisionBinding.RootCommand root;
        final SyntheticKycPreparationBinding.PreparationCommand preparation;
        final OwnedGrantTransactionPort.StageCommand stage;
        final OwnedGrantTransactionPort.OutsidePreparedResult result=new OwnedGrantTransactionPort.OutsidePreparedResult(id(500),
            SyntheticGrantStageBinding.BusinessConclusion.POSITIVE,CANARY,new byte[]{11,12},new byte[]{13,14});
        final SyntheticMockPaymentPlanBinding.ReviewCommand review;
        final SyntheticMockPaymentPlanBinding.ReserveCommand reserve;
        final SyntheticMockPaymentTransactionBinding.PaymentCommand payment;
        final SyntheticTypedContinuationBinding.ContinuationCommand continuation;
        final List<PreparedAction> actions;
        NativeFixture(){
            var rootId=identity(100,1,101);var rootInputs=rootInputs(rootId);
            root=new SyntheticRootProvisionBinding.RootCommand(rootId,rootInputs,new SyntheticRootProvisionBinding.TypedWorkflowPlan(
                id(1),1,application,terms,"synthetic-lane",rootId.targetRunId(),agents));
            preparation=new SyntheticKycPreparationBinding.PreparationCommand(identity(200,1,201),source,List.of(),terms,NOW);
            stage=new OwnedGrantTransactionPort.StageCommand(identity(300,1,301),AllowedAction.EVALUATE_KYC);
            review=new SyntheticMockPaymentPlanBinding.ReviewCommand(identity(400,1,401),id(410),
                SyntheticMockPaymentPlanBinding.ReviewDecision.APPROVE,H,NOW,NOW.plusSeconds(60),CANARY);
            var payId=identity(600,1,601);
            var domain=new SyntheticMockPaymentTransactionBinding.PaymentDomain(payId.grantId(),payId.actionId(),id(611),payId.targetRunId(),
                review.approvalId(),id(612),id(1),1,CUSTOMER,id(613),1000,id(21),POLICY,
                SyntheticMockPaymentTransactionBinding.ReservationState.RESERVED,SyntheticMockPaymentTransactionBinding.ApprovalState.RESERVED);
            reserve=new SyntheticMockPaymentPlanBinding.ReserveCommand(payId,domain,H,NOW);
            var complete=identity(700,1,601);
            var receipt=new SyntheticMockPaymentReceiptCodec.Input(complete.globalRequestId(),ALIAS,complete.operation(),complete.canonicalizationVersion(),
                "SHA-256",new byte[]{1,2,3},complete.grantId(),complete.actionId(),domain.paymentId(),complete.targetRunId(),
                domain.approvalId(),domain.reservationId(),id(1),1,CUSTOMER,domain.applicationId(),1000,id(21),POLICY,
                "EXECUTE_MOCK_PAYMENT","COMMITTED","CONSUMED");
            payment=new SyntheticMockPaymentTransactionBinding.PaymentCommand(new OwnedGrantTransactionPort.StageCommand(complete,AllowedAction.EXECUTE_MOCK_PAYMENT),
                new SyntheticMockPaymentTransactionBinding.DigestBinding(H,"SHA-256",new byte[]{1,2,3}),receipt);
            var next=identity(800,2,801);
            continuation=new SyntheticTypedContinuationBinding.ContinuationCommand(next,
                new SyntheticTypedContinuationBinding.OriginalGenerationOne(new VirtualWorkflowLane.Scope(id(1),1,CUSTOMER),
                    rootId.grantId(),rootId.globalRequestId(),rootId.targetRunId(),0),rootInputs(next),application,terms,"synthetic-next-lane",agents,NOW);
            actions=List.of(action(1,new Root(root)),action(2,new Preparation(preparation)),action(3,new KycCompletion(stage,result)),
                action(4,new Review(review)),action(5,new Reservation(reserve)),action(6,new Payment(payment)),action(7,new Continuation(continuation)));
        }
        SyntheticRootProvisionBinding.RootInputs rootInputs(CommandIdentity i){
            var profile=new SyntheticGrantV2Codec.Profile(16384,8192,8,64,1000,300);
            var a=new SyntheticGrantV2Codec.Action(i.actionId(),i.workflowId(),i.generation(),AllowedAction.EVALUATE_KYC,CUSTOMER,1000,
                id(21),i.targetRunId(),null,H,null,POLICY);
            var payload=object("actionId",a.actionId().toString(),"workflowId",a.workflowId().toString(),"generation",a.generation(),
                "allowedAction",a.allowedAction().name(),"customerId",CUSTOMER,"amountKrw",1000L,"payoutAccountId",id(21).toString(),
                "targetRunId",i.targetRunId().toString(),"sourceResultId",null,"evidenceBundleHash",H,"approvalId",null,"policyVersion",POLICY);
            var c=new SyntheticGrantV2Codec.Claims("FUSE-GRANT-v2","HMAC-SHA256","synthetic-key",i.grantId(),id(1),i.generation(),id(30),
                CANARY,"synthetic-intent","synthetic-issuer","synthetic-source","synthetic-target",null,i.targetRunId(),AllowedAction.EVALUATE_KYC,
                CUSTOMER,1000,id(21),null,H,null,1,i.actionId(),CanonicalJson.sha256(payload),POLICY,id(31),null,100,400);
            return new SyntheticRootProvisionBinding.RootInputs(profile,c,a,SyntheticGrantV2Codec.prepare(profile,c,a));
        }
        Coordinates coordinates(int generation){return new Coordinates(id(1),generation,CUSTOMER,source.documentId(),1,source.contentHash(),POLICY);}
        PreparedAction action(long ref,Payload payload){return new PreparedAction(id(900+ref),payload,binding,coordinates(payload.identity().generation()));}
    }
    static final class AdmissionFixture implements AutoCloseable {
        final LocalVirtualTokenRegistry tokens=new LocalVirtualTokenRegistry(1);
        final LocalVirtualPrincipalRegistry principals=new LocalVirtualPrincipalRegistry(1,1);
        final LocalVirtualAdmissionContext context;
        final LocalVirtualAdmissionContext.Admission admission;
        AdmissionFixture(UUID principalId,long bindingRevision,String alias,Set<TokenRegistryInput.Role> roles,Map<UUID,String> workflows){
            var principal=new LocalVirtualPrincipal(principalId,alias,bindingRevision,LocalVirtualPrincipal.Status.ACTIVE,roles,Set.of(CUSTOMER),workflows,3);
            principals.registerPrepared(principal);var material=TokenMaterialCodec.encode(new byte[32]);
            tokens.registerPrepared(new LocalVirtualTokenRegistry.Credential(id(99),principalId,LocalVirtualTokenRegistry.Status.ACTIVE,
                0,NOW.minusSeconds(1),NOW.plusSeconds(60),bindingRevision,material.fingerprint()));
            context=new LocalVirtualAdmissionContext(new LocalVirtualCurrentVerifier(tokens,principals),tokens);
            admission=context.openRequest(tokens.admitCanonical(material.bearer(),NOW),NOW);
        }
        AdmissionFixture(){this(id(90),0,ALIAS,EnumSet.allOf(TokenRegistryInput.Role.class),Map.of(id(1),CUSTOMER));}
        public void close(){admission.close();}
    }
    private void code(Code expected,org.junit.jupiter.api.function.Executable action){
        var failure=assertThrows(Failure.class,action);assertEquals(expected,failure.code());assertNull(failure.getCause());
    }
    @Test void allSevenNativePayloadsResolveWithFreshCanonicalAdmissionAndExactElevenIdentityFields(){
        var f=new NativeFixture();var catalog=new PreparedTypedActionCatalog(f.actions,7);assertEquals(7,catalog.size());
        assertEquals(EnumSet.allOf(Purpose.class),EnumSet.copyOf(f.actions.stream().map(PreparedAction::purpose).toList()));
        for(var action:f.actions)try(var login=new AdmissionFixture()){
            assertSame(action,catalog.resolveForAdmission(action.commandRef(),action.purpose(),action.identity().globalRequestId(),login.admission,action.coordinates()));
            var meta=catalog.metadata(action.commandRef());assertEquals(action.identity().globalRequestId(),meta.globalRequestId());
            assertEquals(action.coordinates(),meta.coordinates());assertEquals(ALIAS,action.identity().actorId());
            assertEquals(id(1),action.identity().workflowId());assertEquals(CUSTOMER,action.identity().customerId());
            assertEquals("PreparedTypedAction[REDACTED]",action.toString());
        }
    }
    @Test void explicitPurposeOperationTableHasNoStandaloneLoanOrImplicitScope(){
        assertEquals(List.of(SimulationAccess.Operation.START,SimulationAccess.Operation.KYC_OBSERVATION,SimulationAccess.Operation.KYC_OBSERVATION,
            SimulationAccess.Operation.REVIEW,SimulationAccess.Operation.PAYMENT,SimulationAccess.Operation.PAYMENT,SimulationAccess.Operation.RESUME),
            Arrays.stream(Purpose.values()).map(PreparedTypedActionCatalog::operation).toList());
        assertThrows(IllegalArgumentException.class,()->operation(null));
    }
    @Test void selectorBoundDuplicatesAndSnapshotMutationNeverExpandCatalog(){
        var f=new NativeFixture();var supplied=new ArrayList<>(f.actions);var catalog=new PreparedTypedActionCatalog(supplied,7);supplied.clear();
        assertEquals(7,catalog.size());assertThrows(IllegalArgumentException.class,()->new PreparedTypedActionCatalog(f.actions,6));
        assertThrows(IllegalArgumentException.class,()->new PreparedTypedActionCatalog(List.of(f.actions.get(0),f.actions.get(0)),2));
        var original=f.actions.get(0);var sameRequest=new PreparedAction(id(999),original.payload(),original.principal(),original.coordinates());
        assertThrows(IllegalArgumentException.class,()->new PreparedTypedActionCatalog(List.of(original,sameRequest),2));
        assertThrows(IllegalArgumentException.class,()->catalog.metadata(null));code(Code.UNKNOWN_REFERENCE,()->catalog.metadata(id(9999)));
    }
    @Test void requestPurposeCoordinatesAndMissingAdmissionRefuseAfterValidControl(){
        var f=new NativeFixture();var action=f.actions.get(0);var catalog=new PreparedTypedActionCatalog(f.actions,7);
        try(var login=new AdmissionFixture()){
            assertSame(action,catalog.resolveForAdmission(action.commandRef(),action.purpose(),action.identity().globalRequestId(),login.admission,action.coordinates()));
            code(Code.INVALID_REQUEST,()->catalog.resolveForAdmission(action.commandRef(),Purpose.CONTINUATION,action.identity().globalRequestId(),login.admission,action.coordinates()));
            code(Code.INVALID_REQUEST,()->catalog.resolveForAdmission(action.commandRef(),action.purpose(),id(9999),login.admission,action.coordinates()));
            var c=action.coordinates();
            var mismatches=List.of(new Coordinates(id(999),c.generation(),c.customerId(),c.documentId(),c.documentVersion(),c.sourceContentHash(),c.policyVersion()),
                new Coordinates(c.workflowId(),c.generation()+1,c.customerId(),c.documentId(),c.documentVersion(),c.sourceContentHash(),c.policyVersion()),
                new Coordinates(c.workflowId(),c.generation(),"synthetic-other",c.documentId(),c.documentVersion(),c.sourceContentHash(),c.policyVersion()),
                new Coordinates(c.workflowId(),c.generation(),c.customerId(),id(999),c.documentVersion(),c.sourceContentHash(),c.policyVersion()),
                new Coordinates(c.workflowId(),c.generation(),c.customerId(),c.documentId(),c.documentVersion()+1,c.sourceContentHash(),c.policyVersion()),
                new Coordinates(c.workflowId(),c.generation(),c.customerId(),c.documentId(),c.documentVersion(),"b".repeat(64),c.policyVersion()),
                new Coordinates(c.workflowId(),c.generation(),c.customerId(),c.documentId(),c.documentVersion(),c.sourceContentHash(),"synthetic-other-policy"));
            for(var wrong:mismatches)code(Code.BINDING_UNCONFIRMED,()->catalog.resolveForAdmission(action.commandRef(),action.purpose(),action.identity().globalRequestId(),login.admission,wrong));
            code(Code.UNAUTHENTICATED,()->catalog.resolveForAdmission(action.commandRef(),action.purpose(),action.identity().globalRequestId(),null,c));
        }
    }
    @Test void otherPrincipalAliasRevisionOrRoleCannotUseMatchingPreparedSelector(){
        var f=new NativeFixture();var action=f.actions.get(0);var catalog=new PreparedTypedActionCatalog(f.actions,7);
        for(int mode=0;mode<4;mode++)try(var login=new AdmissionFixture(mode==0?id(999):id(90),mode==1?1:0,
                mode==2?"synthetic-other-alias":ALIAS,mode==3?Set.of(TokenRegistryInput.Role.LOAN_REVIEWER):EnumSet.allOf(TokenRegistryInput.Role.class),Map.of(id(1),CUSTOMER))){
            code(Code.FORBIDDEN,()->catalog.resolveForAdmission(action.commandRef(),action.purpose(),action.identity().globalRequestId(),login.admission,action.coordinates()));
        }
        try(var login=new AdmissionFixture(id(90),0,ALIAS,Set.of(TokenRegistryInput.Role.CUSTOMER),Map.of())){
            code(Code.FORBIDDEN,()->catalog.resolveForAdmission(action.commandRef(),action.purpose(),action.identity().globalRequestId(),login.admission,action.coordinates()));
        }
    }
    @Test void closedAdmissionAndDifferentLatchedOperationRemainRejected(){
        var f=new NativeFixture();var action=f.actions.get(0);var catalog=new PreparedTypedActionCatalog(f.actions,7);
        var login=new AdmissionFixture();login.close();
        assertThrows(LocalVirtualAdmissionContext.Failure.class,()->catalog.resolveForAdmission(action.commandRef(),action.purpose(),action.identity().globalRequestId(),login.admission,action.coordinates()));
        try(var other=new AdmissionFixture()){
            assertEquals(LocalVirtualAccessPolicy.Decision.ALLOW,other.admission.authorize(SimulationAccess.Operation.READ,id(1),CUSTOMER));
            code(Code.FORBIDDEN,()->catalog.resolveForAdmission(action.commandRef(),action.purpose(),action.identity().globalRequestId(),other.admission,action.coordinates()));
        }
    }
    @Test void principalActorAndSourceCoordinateMismatchCannotEnterPreparedCatalog(){
        var f=new NativeFixture();var original=f.actions.get(0);var c=original.coordinates();
        assertThrows(IllegalArgumentException.class,()->new PreparedAction(id(990),original.payload(),new PrincipalBinding(id(90),0,"synthetic-wrong",CANARY),c));
        assertThrows(IllegalArgumentException.class,()->new PreparedAction(id(990),original.payload(),f.binding,
            new Coordinates(c.workflowId(),c.generation(),c.customerId(),id(999),c.documentVersion(),c.sourceContentHash(),c.policyVersion())));
    }
}
