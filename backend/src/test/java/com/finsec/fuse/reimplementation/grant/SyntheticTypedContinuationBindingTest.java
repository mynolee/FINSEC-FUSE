package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.*;
import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import com.finsec.fuse.reimplementation.simulation.VirtualWorkflowLane.Scope;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import static com.finsec.fuse.reimplementation.grant.SyntheticTypedContinuationBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBindingTest.changed;
import static com.finsec.fuse.reimplementation.grant.VirtualGrantFactResolverTest.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.Status;
import static org.junit.jupiter.api.Assertions.*;

/** Pure synthetic joins only: no owned-query completeness, authorization or commit proof. NOT_RUN. */
final class SyntheticTypedContinuationBindingTest {
    static final class Fixture {
        final SyntheticRootProvisionBindingTest.RootFixture old=new SyntheticRootProvisionBindingTest.RootFixture();
        final Scope scope=new Scope(old.plan.workflowId(),1,old.application.customerId());
        final Map<AllowedAction,SyntheticRootProvisionBinding.AgentReference> agents=new LinkedHashMap<>(old.suppliedAgents);
        final ContinuationCommand command;
        Fixture() throws Exception {
            var action=changed(old.node.action(),"generation",2);
            action=changed(action,"actionId",id(992));action=changed(action,"targetRunId",id(993));
            var claims=changed(old.node.claims(),"generation",2);
            claims=changed(claims,"grantId",id(991));claims=changed(claims,"actionId",action.actionId());
            claims=changed(claims,"targetRunId",action.targetRunId());claims=changed(claims,"payloadHash",payload(action));
            var root=new SyntheticRootProvisionBinding.RootInputs(profile(),claims,action,SyntheticGrantV2Codec.prepare(profile(),claims,action));
            var identity=changed(old.identity,"generation",2);identity=changed(identity,"grantId",claims.grantId());
            identity=changed(identity,"actionId",claims.actionId());identity=changed(identity,"targetRunId",claims.targetRunId());
            command=new ContinuationCommand(identity,new OriginalGenerationOne(scope,old.identity.grantId(),
                    old.identity.globalRequestId(),old.identity.targetRunId(),0),root,old.application,old.terms,
                    "synthetic-next-lane",agents,Instant.ofEpochSecond(150));
        }
        CurrentBindings current() {
            var origin=new VirtualGrantGenerationHistory.GenerationRecord(scope,old.identity.grantId(),
                    old.identity.globalRequestId(),old.identity.targetRunId(),old.source.documentId(),
                    old.source.documentVersion(),old.terms,null);
            return new CurrentBindings(origin,null,new SyntheticKycPreparationBinding.SourceCoordinate(
                    old.source.documentId(),old.source.documentVersion()),old.application.businessReference(),
                    old.application.amountKrw(),old.application.payoutAccountId(),"BLOCKED",null,
                    new VirtualGrantEvaluationAccounting.Counters(0,0,0,false,false),PendingDisposition.VERIFIED_EMPTY,ResumeReadiness.READY);
        }
    }
    private static void invalid(Executable work) {
        var e=assertThrows(IllegalArgumentException.class,work);assertEquals("INVALID_CONTINUATION",e.getMessage());assertNull(e.getCause());
    }
    @Test void explicitOriginalObservationZeroProducesNextGenerationWithoutClaimingExistingHead() throws Exception {
        var f=new Fixture();assertEquals(2,f.command.requestedScope().generation());assertEquals(1,f.command.nextRevision());
        assertInstanceOf(OriginalGenerationOne.class,f.command.prior());checkBindings(f.command,f.current());
        assertEquals("ContinuationCommand[REDACTED]",f.command.toString());
    }
    @Test void commandCopiesAgentsAndPlanOmitsSourceText() throws Exception {
        var f=new Fixture();f.agents.clear();assertEquals(1,f.command.stageAgents().size());
        assertThrows(UnsupportedOperationException.class,()->f.command.stageAgents().clear());
        var plan=PlanBinding.from(f.command);assertEquals(f.old.source.contentHash(),plan.contentHash());
        assertEquals("PlanBinding[REDACTED_NO_SOURCE_TEXT]",plan.toString());
        assertFalse(plan.toString().contains(f.old.source.text()));
    }
    @Test void revisionOverflowAndNonSecondObservationCannotFormCommand() throws Exception {
        var f=new Fixture();var prior=new OriginalGenerationOne(f.scope,f.old.identity.grantId(),f.old.identity.globalRequestId(),f.old.identity.targetRunId(),Long.MAX_VALUE);
        invalid(()->changed(f.command,"prior",prior));
        invalid(()->changed(f.command,"observedAt",Instant.ofEpochSecond(150,1)));
        invalid(()->changed(f.command,"observedAt",Instant.ofEpochSecond(-1)));
        invalid(()->new OriginalGenerationOne(new Scope(f.scope.workflowId(),2,f.scope.customerId()),id(1),id(2),id(3),0));
    }
    @Test void requestIdentityAndKycAgentMustMatchExplicitNewRoot() throws Exception {
        var f=new Fixture();var wrong=changed(f.command.identity(),"targetRunId",id(999));
        invalid(()->changed(f.command,"identity",wrong));
        invalid(()->changed(f.command,"stageAgents",Map.of()));
        invalid(()->changed(f.command,"stageAgents",Map.of(AllowedAction.EVALUATE_KYC,
                new SyntheticRootProvisionBinding.AgentReference("foreign-agent",1))));
    }
    @Test void requestedAndCommittedGenerationsDifferOnlyForDedicatedDenialReceipt() throws Exception {
        var f=new Fixture();var advanced=new ContinuationReceipt(1,ContinuationKind.ADVANCED,f.command);
        var denied=new ContinuationReceipt(1,ContinuationKind.DENIED,f.command);
        assertTrue(advanced.matches(f.command));assertTrue(denied.matches(f.command));
        assertEquals(2,advanced.committedGeneration());assertEquals(1L,advanced.publishedHeadRevision().longValue());
        assertEquals(1,denied.committedGeneration());assertNull(denied.publishedHeadRevision());
        assertFalse(advanced.actualAuthority());assertFalse(denied.actualAuthority());assertFalse(advanced.durable());
        invalid(()->changed(denied,"publishedHeadRevision",1L));invalid(()->changed(advanced,"committedGeneration",1));
    }
    @Test void receiptMatchingIncludesSafePlanAndExactIdentity() throws Exception {
        var f=new Fixture();var receipt=new ContinuationReceipt(1,ContinuationKind.ADVANCED,f.command);
        assertFalse(receipt.matches(changed(f.command,"laneReference","synthetic-other-lane")));
        var identity=changed(f.command.identity(),"globalRequestId",id(999));
        assertFalse(receipt.matches(changed(f.command,"identity",identity)));assertFalse(receipt.matches(null));
        assertEquals("ContinuationReceipt[VIRTUAL_REDACTED]",receipt.toString());
    }
    @Test void currentTicketMustMatchPriorOriginAndBusinessIdentity() throws Exception {
        var f=new Fixture();var good=f.current();checkBindings(f.command,good);
        var wrong=new CurrentBindings(good.origin(),new VirtualGrantGenerationHistory.ExpectedHead(f.scope,id(991),0),
                good.currentSource(),good.businessReference(),good.amountKrw(),good.payoutAccountId(),good.oldState(),null,
                good.counters(),good.pendingDisposition(),good.resumeReadiness());
        invalid(()->checkBindings(f.command,wrong));
        var foreign=new CurrentBindings(good.origin(),null,good.currentSource(),"foreign-business",good.amountKrw(),
                good.payoutAccountId(),good.oldState(),null,good.counters(),good.pendingDisposition(),good.resumeReadiness());
        invalid(()->checkBindings(f.command,foreign));
    }
    @Test void committedUnknownAndOrdinaryRefusalOutcomeShapesRemainDistinct() throws Exception {
        var f=new Fixture();var receipt=new ContinuationReceipt(1,ContinuationKind.DENIED,f.command);
        var committed=new ContinuationOutcome(Status.VIRTUAL_COMMITTED_IN_PROCESS,receipt,ContinuationEffect.COMMITTED_IN_PROCESS);
        var unknown=new ContinuationOutcome(Status.COMMIT_UNKNOWN,null,ContinuationEffect.UNKNOWN);
        var refused=new ContinuationOutcome(Status.REFUSED_BEFORE_ADMISSION,null,ContinuationEffect.NO_NEW_CONTINUATION_ATTEMPT_THIS_INVOCATION);
        assertFalse(committed.actualAuthority());assertFalse(unknown.durable());assertNull(refused.receipt());
        invalid(()->new ContinuationOutcome(Status.COMMIT_UNKNOWN,receipt,ContinuationEffect.UNKNOWN));
        invalid(()->new ContinuationOutcome(Status.VIRTUAL_COMMITTED_IN_PROCESS,null,ContinuationEffect.COMMITTED_IN_PROCESS));
        invalid(()->new ContinuationOutcome(Status.REFUSED_BEFORE_ADMISSION,null,ContinuationEffect.UNKNOWN));
    }
    @Test void suppliedResolvedPositiveJoinsIssuerKeyAndExactObservationWithoutAuthority() throws Exception {
        var f=new Fixture();var resolved=new ResolvedContinuation(f.command,f.current(),f.old.issuer,f.old.keyFacts);
        checkResolved(f.command,resolved);
        var key=f.old.keyFacts;
        var wrongTime=new SyntheticGrantTemporalAssessment.TemporalFacts(151,key.time().issuedAtEpochSecond(),
                key.time().expiresAtEpochSecond(),key.time().chainPosition(),key.time().parentExpiresAtEpochSecond());
        var wrongKey=new SyntheticRootProvisionBinding.KeyFacts(key.expected(),key.snapshot(),key.bindingChanged(),
                key.material(),wrongTime,key.revocation(),key.current());
        invalid(()->checkResolved(f.command,new ResolvedContinuation(f.command,f.current(),f.old.issuer,wrongKey)));
    }
    @Test void pendingUnknownOrNotReadyCannotPassResolvedFreshContinuation() throws Exception {
        var f=new Fixture();var b=f.current();
        for(var pending:List.of(PendingDisposition.COHERENT_NONEMPTY,PendingDisposition.UNCONFIRMED)) {
            var blocked=new CurrentBindings(b.origin(),null,b.currentSource(),b.businessReference(),b.amountKrw(),
                    b.payoutAccountId(),b.oldState(),null,b.counters(),pending,ResumeReadiness.READY);
            invalid(()->checkResolved(f.command,new ResolvedContinuation(f.command,blocked,f.old.issuer,f.old.keyFacts)));
        }
        for(var readiness:List.of(ResumeReadiness.KNOWN_NOT_READY,ResumeReadiness.UNCONFIRMED)) {
            var blocked=new CurrentBindings(b.origin(),null,b.currentSource(),b.businessReference(),b.amountKrw(),
                    b.payoutAccountId(),b.oldState(),null,b.counters(),PendingDisposition.VERIFIED_EMPTY,readiness);
            invalid(()->checkResolved(f.command,new ResolvedContinuation(f.command,blocked,f.old.issuer,f.old.keyFacts)));
        }
    }
    @Test void remediatedCandidateSourceIsNotMistakenForOldWorkflowCoordinate() throws Exception {
        var f=new Fixture();var source=new SimulationSpec.Source(id(999),2,"synthetic replacement body",
                SimulationSpec.rawHash("synthetic replacement body"),true);
        var app=changed(f.command.application(),"source",source);
        var replacement=changed(f.command,"application",app);
        checkBindings(replacement,f.current());
        // Pure mechanical compatibility only: actual catalog/holds/ticket remain resolver obligations.
        assertNotEquals(PlanBinding.from(f.command).documentId(),PlanBinding.from(replacement).documentId());
        assertFalse(new ContinuationReceipt(1,ContinuationKind.ADVANCED,f.command).matches(replacement));
    }

}
