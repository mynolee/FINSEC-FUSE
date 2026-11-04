package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticKycPreparationBinding.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;

class SyntheticKycPreparationBindingTest {
    static UUID id(int n) { return new UUID(0,n); }
    static final Instant NOW=Instant.parse("2026-01-01T00:00:00Z");
    static final String TEXT="synthetic document canary";
    static SimulationSpec.RiskTerms terms() {
        return new SimulationSpec.RiskTerms("synthetic-policy",2,3,1,20,0,2,Duration.ofMinutes(1));
    }
    static CommandIdentity identity() {
        return new CommandIdentity("synthetic-actor",id(1),"PREPARE_KYC","synthetic-v1","synthetic-digest",id(2),id(3),id(4),id(5),1,"synthetic-customer");
    }
    static SimulationSpec.Fact fact(int n,String customer,boolean active) {
        return new SimulationSpec.Fact(id(n),customer,SimulationSpec.Kind.ID_DOC,SimulationSpec.Outcome.PASS,active,NOW.minusSeconds(1),NOW.plusSeconds(1));
    }
    static PreparationCommand command(List<SimulationSpec.Fact> facts,boolean safe) {
        return new PreparationCommand(identity(),new SimulationSpec.Source(id(6),1,TEXT,SimulationSpec.rawHash(TEXT),safe),facts,terms(),NOW);
    }
    static PreparationCommand command() {
        return command(List.of(fact(9,"synthetic-customer",true),fact(8,"synthetic-customer",true)),true);
    }
    static FreshBindings binding(PreparationCommand c,GrantSnapshot g,SourceCoordinate source,SimulationSpec.RiskTerms terms) {
        return new FreshBindings(g,"KYC_PENDING",new VirtualGrantEvaluationAccounting.Counters(0,0,0,false,false),20,source,terms,false);
    }
    static GrantSnapshot grant(PreparationCommand c,GrantState state,AllowedAction action) {
        var i=c.identity(); return new GrantSnapshot(i.grantId(),i.actionId(),i.targetRunId(),i.workflowId(),i.generation(),i.customerId(),action,state);
    }
    @Test void canonicalOrderingAndModelHashInsertionPreserveLegacyInput() {
        var c=command(); var p=prepareRequested(c);
        assertEquals(List.of("requestId","workflowId","generation","runId","customerId","policyVersion","evidenceFacts","documents"),new ArrayList<>(p.canonicalInput().keySet()));
        assertEquals(List.of("requestId","workflowId","generation","runId","customerId","policyVersion","inputSnapshotHash","evidenceFacts","documents"),new ArrayList<>(p.modelInput().keySet()));
        assertEquals(CanonicalJson.orderedSha256(p.canonicalInput()),p.inputSnapshotHash());
        assertEquals(p.inputSnapshotHash(),p.modelInput().get("inputSnapshotHash"));
        assertEquals(p.canonicalInput().get("evidenceFacts"),p.modelInput().get("evidenceFacts"));
        var rows=(List<?>)p.canonicalInput().get("evidenceFacts");
        assertEquals(id(8).toString(),((Map<?,?>)rows.get(0)).get("evidenceId"));
        assertEquals(id(4).toString(),p.canonicalInput().get("runId"));
    }
    @Test void factInsertionOrderIsNotPartOfSnapshotButPreparedTimeIsDescriptorData() {
        var c=command(); var reverse=command(List.of(c.facts().get(1),c.facts().get(0)),true);
        assertEquals(prepareRequested(c).canonicalInput(),prepareRequested(reverse).canonicalInput());
        assertEquals(prepareRequested(c).inputSnapshotHash(),prepareRequested(reverse).inputSnapshotHash());
        var later=new PreparationCommand(c.identity(),c.source(),c.facts(),c.terms(),NOW.plusNanos(1));
        assertNotEquals(descriptor(c),descriptor(later));
    }
    @Test void defensiveCopiesIncludeNestedCanonicalAndModelMaterial() {
        var facts=new ArrayList<>(command().facts()); var c=command(facts,true); facts.clear();
        assertEquals(2,c.facts().size()); assertThrows(UnsupportedOperationException.class,()->c.facts().clear());
        var p=prepareRequested(c);
        assertThrows(UnsupportedOperationException.class,()->p.canonicalInput().clear());
        assertThrows(UnsupportedOperationException.class,()->p.modelInput().clear());
        var documents=(List<?>)p.canonicalInput().get("documents");
        assertThrows(UnsupportedOperationException.class,()->documents.clear());
        assertThrows(UnsupportedOperationException.class,()->((Map<?,?>)documents.get(0)).clear());
    }
    @Test void unsafeDuplicateForeignInactiveAndExpiredFactsRefuseWithoutNegativeResult() {
        var f=fact(8,"synthetic-customer",true);
        for(var c:List.of(command(List.of(f),false),command(List.of(f,f),true),command(List.of(fact(8,"synthetic-other",true)),true),command(List.of(fact(8,"synthetic-customer",false)),true),command(List.of(new SimulationSpec.Fact(id(8),"synthetic-customer",SimulationSpec.Kind.ID_DOC,SimulationSpec.Outcome.PASS,true,NOW.minusSeconds(2),NOW)),true))) {
            var e=assertThrows(IllegalArgumentException.class,()->prepareRequested(c));
            assertEquals("INVALID_KYC_PREPARATION",e.getMessage()); assertNull(e.getCause());
        }
    }
    @Test void factCountAndNullsAreRejectedAtCommandBoundary() {
        var facts=new ArrayList<SimulationSpec.Fact>(); for(int n=0;n<11;n++) facts.add(fact(20+n,"synthetic-customer",true));
        assertThrows(IllegalArgumentException.class,()->command(facts,true));
        facts.clear(); facts.add(null); assertThrows(IllegalArgumentException.class,()->command(facts,true));
    }
    @Test void bindingsRequireActualCoordinateTermsAndIssuedKycScope() {
        var c=command(); var g=grant(c,GrantState.ISSUED,AllowedAction.EVALUATE_KYC); var coordinate=new SourceCoordinate(id(6),1);
        assertDoesNotThrow(()->checkBindings(c,binding(c,g,coordinate,terms())));
        assertThrows(IllegalArgumentException.class,()->checkBindings(c,binding(c,g,new SourceCoordinate(id(6),2),terms())));
        assertThrows(IllegalArgumentException.class,()->checkBindings(c,binding(c,grant(c,GrantState.CONSUMED,AllowedAction.EVALUATE_KYC),coordinate,terms())));
        assertThrows(IllegalArgumentException.class,()->checkBindings(c,binding(c,grant(c,GrantState.ISSUED,AllowedAction.CREATE_LOAN_RECOMMENDATION),coordinate,terms())));
        var changed=new SimulationSpec.RiskTerms("synthetic-other",2,3,1,20,0,2,Duration.ofMinutes(1));
        assertThrows(IllegalArgumentException.class,()->checkBindings(c,binding(c,g,coordinate,changed)));
    }
    @Test void internalRawTextIsExplicitWhileDescriptorAndDiagnosticsAreRedacted() {
        var c=command(); var p=prepareRequested(c); var d=descriptor(c);
        assertEquals(TEXT,((Map<?,?>)((List<?>)p.modelInput().get("documents")).get(0)).get("text"));
        assertEquals(c.source().contentHash(),d.source().contentHash());
        var receipt=new PreparationReceipt(c.identity(),d,p.inputSnapshotHash(),Decision.PREPARED,Refusal.NONE,2,1,2);
        for(Object value:List.of(c,p,d,d.source(),receipt)) assertFalse(value.toString().contains(TEXT));
        assertEquals("InputDescriptor[REDACTED]",d.toString()); assertFalse(receipt.actualAuthority());
    }
    @Test void outcomeCannotPromoteUnknownOrRefusalToAuthorityOrReceiptSuccess() {
        var unknown=new PreparationOutcome(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH,null,PreparationEffect.UNKNOWN);
        assertFalse(unknown.actualAuthority()); assertFalse(unknown.durable()); assertFalse(unknown.executionAuthorityGranted());
        assertThrows(IllegalArgumentException.class,()->new PreparationOutcome(Status.COMMIT_UNKNOWN,null,PreparationEffect.NO_NEW_PREPARATION_ATTEMPT_THIS_INVOCATION));
        var c=command(); var p=prepareRequested(c);
        assertThrows(IllegalArgumentException.class,()->new PreparationReceipt(c.identity(),descriptor(c),p.inputSnapshotHash(),Decision.ON_HOLD,Refusal.RISK_LIMIT_EXCEEDED,1,0,0));
        assertThrows(IllegalArgumentException.class,()->new PreparationOutcome(Status.VIRTUAL_COMMITTED_IN_PROCESS,null,PreparationEffect.COMMITTED_IN_PROCESS));
    }
}
