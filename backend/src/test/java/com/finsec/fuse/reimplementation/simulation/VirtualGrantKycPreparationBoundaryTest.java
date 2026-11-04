package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.grant.*;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticRootProvisionBinding.*;
import static org.junit.jupiter.api.Assertions.*;

class VirtualGrantKycPreparationBoundaryTest {
    static final class Scenario {
        final VirtualGrantWorkflowBridgeTest.Fixture f=new VirtualGrantWorkflowBridgeTest.Fixture();
        final SimulationSpec.RiskTerms terms;
        final PreparationCommand command;
        final SyntheticKycPreparationService service;
        int currentChecks;
        Scenario(int limit){
            var old=f.root.workflowPlan();var t=f.terms;
            terms=new SimulationSpec.RiskTerms(t.policyVersion(),t.kycPoints(),t.loanPoints(),t.payPoints(),limit,0,t.maxAutomaticKycRuns(),t.approvalLifetime());
            var plan=new TypedWorkflowPlan(old.workflowId(),old.generation(),old.application(),terms,old.laneReference(),old.targetRunId(),old.stageAgents());
            var root=new RootCommand(f.root.identity(),f.root.inputs(),plan);
            var product=f.typed();f.facts.next();
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,product.grantWorkflows().startTyped(f.context,root).status());
            var c=f.preparation();command=new PreparationCommand(c.identity(),c.source(),c.facts(),terms,c.preparedAt());
            var journal=new VirtualGrantTransactionJournal(f.f.store,()->VirtualGrantWorkflowBridgeTest.id(f.tokens.incrementAndGet()),65536);
            service=new SyntheticKycPreparationService(journal,(context,supplied,tx)->{
                currentChecks++;
                if(!f.f.permitted.get() || !context.actorId().equals(f.context.actorId()))return Gate.REFUSED;
                return supplied.equals(command) && supplied.source().equals(f.f.catalog.source(supplied.source().documentId(),supplied.source().documentVersion()))
                        && supplied.facts().equals(f.f.catalog.factsFor(supplied.identity().customerId(),supplied.preparedAt())) ? Gate.CLEAR:Gate.UNKNOWN;
            });
        }
        Map<String,Object> workflow(){return f.f.store.snapshot().get("virtual_workflows").get(VirtualGrantWorkflowBridgeTest.id(1).toString());}
        int rows(String table){return f.f.store.snapshot().getOrDefault(table,Map.of()).size();}
    }
    @Test void insufficientFirstPreparationCommitsOnHoldDenyReasonWithoutChargingOrConsuming(){
        Scenario s=new Scenario(0);var out=s.service.prepare(s.f.context,s.command);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,out.status());assertNotNull(out.receipt());
        assertEquals(Decision.ON_HOLD,out.receipt().decision());assertEquals(Refusal.RISK_LIMIT_EXCEEDED,out.receipt().refusal());
        assertEquals(0,out.receipt().chargedPoints());assertEquals(0,out.receipt().kycRunsAfter());assertEquals(0,out.receipt().usedRiskAfter());
        assertEquals("ON_HOLD",s.workflow().get("state"));assertEquals("DENY",s.workflow().get("lastDecision"));
        assertEquals(List.of("RISK_LIMIT_EXCEEDED"),s.workflow().get("reasonCodes"));
        assertEquals(0,s.rows("virtual_grant_profile_kyc_preparations"));assertEquals(0,s.rows("virtual_grant_profile_kyc_inputs"));
        assertEquals(0,s.rows("virtual_grant_profile_stage_charges"));assertEquals(0,s.rows("virtual_grant_profile_results"));
        var grants=s.f.f.store.snapshot().get("virtual_grant_profile_grants");
        assertEquals(1,grants.size());assertEquals("ISSUED",grants.values().iterator().next().get("state"));
        assertFalse(out.actualAuthority());assertFalse(out.durable());assertEquals(0,s.f.providers.get());
    }
    @Test void exactRefusalReplayIsZeroEffectButCurrentDenialStillPrecedesHistory(){
        Scenario s=new Scenario(0);var first=s.service.prepare(s.f.context,s.command);var before=s.f.f.store.snapshot();
        int checks=s.currentChecks;var replay=s.service.prepare(s.f.context,s.command);
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,replay.status());assertEquals(first.receipt(),replay.receipt());
        assertEquals(checks+1,s.currentChecks);assertEquals(before,s.f.f.store.snapshot());
        s.f.f.permitted.set(false);var denied=s.service.prepare(s.f.context,s.command);
        assertEquals(Status.REFUSED_BEFORE_ADMISSION,denied.status());assertNull(denied.receipt());assertEquals(before,s.f.f.store.snapshot());
    }
    @Test void exactCapacityAndSufficientCapacityPrepareOnceWithoutConsumptionOrDispatch(){
        for(int limit:List.of(1,2)){
            Scenario s=new Scenario(limit);var out=s.service.prepare(s.f.context,s.command);
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,out.status());assertEquals(Decision.PREPARED,out.receipt().decision());
            assertEquals(Refusal.NONE,out.receipt().refusal());assertEquals(1,out.receipt().chargedPoints());
            assertEquals(1,out.receipt().kycRunsAfter());assertEquals(1,out.receipt().usedRiskAfter());
            assertEquals("KYC_PENDING",s.workflow().get("state"));assertEquals(1,s.rows("virtual_grant_profile_kyc_preparations"));
            assertEquals(1,s.rows("virtual_grant_profile_stage_charges"));assertEquals(0,s.rows("virtual_grant_profile_results"));
            var before=s.f.f.store.snapshot();assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,s.service.prepare(s.f.context,s.command).status());
            assertEquals(before,s.f.f.store.snapshot());assertEquals(0,s.f.providers.get());assertFalse(out.actualAuthority());
        }
    }
}
