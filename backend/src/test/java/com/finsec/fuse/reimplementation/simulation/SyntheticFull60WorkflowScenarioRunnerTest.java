package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.simulation.VirtualWorkflowService.*;

/** Actual public synthetic operations only; NOT_RUN, no baseline/provider/authority claim. */
class SyntheticFull60WorkflowScenarioRunnerTest {
    @SuppressWarnings("unchecked") private Map<String,Object> decoded() throws Exception {
        byte[] raw=Files.readAllBytes(Path.of("../evaluation/fixtures/synthetic-full60-v1.json"));
        assertEquals(122175,raw.length);
        assertEquals("cea38d1b91f6563be1e7d123d3d942eafe8d78d9a6da7d3e66f2c581b3d0d3b5",HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(raw)));
        return JsonMapper.builder().build().readValue(raw,Map.class);
    }
    private SyntheticFull60FixtureAdapter.Fixture fixture() throws Exception{return SyntheticFull60FixtureAdapter.adapt(decoded());}
    private SimulationSpec.RiskTerms terms(){return new SimulationSpec.RiskTerms("SYNTHETIC-SCENARIO-TEST",1,2,3,100,5,2,Duration.ofMinutes(5));}
    private SyntheticFull60WorkflowScenarioRunner runner(SyntheticFull60FixtureAdapter.Fixture f,String id){
        var sequence=new AtomicLong(1000);
        return new SyntheticFull60WorkflowScenarioRunner(f,terms(),new SimulationAccess((a,o,w,c)->true),new ActorRef("synthetic-scenario-actor"),
            Clock.fixed(f.byId(id).seed().observationTime(),ZoneOffset.UTC),()->new UUID(0,sequence.incrementAndGet()));
    }
    private void preapprovalOnly(SyntheticFull60WorkflowScenarioRunner.Execution r){
        assertEquals(SyntheticFull60WorkflowScenarioRunner.Reached.OBSERVED,r.reached());
        assertEquals(1,r.committedRowCounts().get(WORKFLOWS));
        assertEquals(0,r.committedRowCounts().get(PAYMENTS));assertEquals(0,r.committedRowCounts().get(RESERVATIONS));
        assertEquals("FUSE",r.supportedArm());assertEquals("INCOMPLETE_PAIR",r.pairStatus());
        assertFalse(r.baselineAvailable());assertFalse(r.measuredMetricsAvailable());assertFalse(r.productionAuthority());
    }
    @Test void twoVerifiedPositiveProfilesReachActualWaitingWithoutPaymentOrBaseline() throws Exception {
        var f=fixture();
        for(String id:List.of("synthetic-full60-c001","synthetic-full60-c004")){
            var result=runner(f,id).runCase(id);preapprovalOnly(result);
            assertEquals("WAIT_APPROVAL",result.workflow().get("state"));assertEquals("WAIT_APPROVAL",result.workflow().get("lastDecision"));
            assertEquals(0,result.committedRowCounts().get(APPROVALS));assertEquals(2,result.committedRowCounts().get(RESULTS));
        }
    }
    @Test void negativeStatusAndEvidenceProfilesReachActualDenialWithoutFakeExpectedLookup() throws Exception {
        var f=fixture();
        for(String id:List.of("synthetic-full60-c002","synthetic-full60-c007","synthetic-full60-c058")){
            var result=runner(f,id).runCase(id);preapprovalOnly(result);
            assertEquals("BLOCKED",result.workflow().get("state"));assertEquals("DENY",result.workflow().get("lastDecision"));
            assertEquals(0,result.committedRowCounts().get(APPROVALS));assertEquals(0,result.committedRowCounts().get(RESULTS));
        }
    }
    @Test void freshStorePerCaseDoesNotAccumulateAnotherCasesCommittedRows() throws Exception {
        var f=fixture();var runner=runner(f,"synthetic-full60-c001");
        var first=runner.runCase("synthetic-full60-c001");var second=runner.runCase("synthetic-full60-c004");
        preapprovalOnly(first);preapprovalOnly(second);assertNotEquals(first.workflowId(),second.workflowId());
        assertNotEquals(first.workflow().get("customerId"),second.workflow().get("customerId"));
        assertEquals(1,first.committedRowCounts().get(WORKFLOWS));assertEquals(1,second.committedRowCounts().get(WORKFLOWS));
        assertThrows(UnsupportedOperationException.class,()->first.workflow().put("state","FAKE"));
        assertThrows(UnsupportedOperationException.class,()->first.committedRowCounts().put(PAYMENTS,1));
    }
    @Test void capabilityIsPreparedRegistryOnlyAndUnknownCaseNeverInvokesAuthority() throws Exception {
        var f=fixture();var calls=new AtomicLong();
        var r=new SyntheticFull60WorkflowScenarioRunner(f,terms(),new SimulationAccess((a,o,w,c)->{calls.incrementAndGet();return false;}),new ActorRef("synthetic-scenario-actor"),Clock.fixed(f.byId("synthetic-full60-c001").seed().observationTime(),ZoneOffset.UTC),()->new UUID(0,1));
        var capability=r.capability();assertEquals(60,capability.caseIds().size());assertFalse(capability.baselineAvailable());assertFalse(capability.providerInvoked());assertFalse(capability.productionAuthority());
        assertThrows(IllegalArgumentException.class,()->r.runCase("synthetic-unsupported"));assertEquals(0,calls.get());
        var failure=assertThrows(SimulationFailure.class,()->r.runCase("synthetic-full60-c001"));assertEquals(403,failure.status());assertTrue(calls.get()>0);
    }
    @Test void staleClockDuplicateIdentifiersAndMalformedFixtureDoNotBecomeResults() throws Exception {
        var f=fixture();var c=f.byId("synthetic-full60-c001");
        var stale=new SyntheticFull60WorkflowScenarioRunner(f,terms(),new SimulationAccess((a,o,w,cust)->true),new ActorRef("synthetic-scenario-actor"),Clock.fixed(c.seed().observationTime().plusSeconds(1),ZoneOffset.UTC),()->new UUID(0,1));
        assertThrows(IllegalArgumentException.class,()->stale.runCase(c.caseId()));
        var duplicate=new SyntheticFull60WorkflowScenarioRunner(f,terms(),new SimulationAccess((a,o,w,cust)->true),new ActorRef("synthetic-scenario-actor"),Clock.fixed(c.seed().observationTime(),ZoneOffset.UTC),()->new UUID(0,1));
        assertThrows(IllegalStateException.class,()->duplicate.runCase(c.caseId()));
        var malformed=new LinkedHashMap<>(decoded());malformed.put("cases",List.of());
        assertThrows(IllegalArgumentException.class,()->SyntheticFull60FixtureAdapter.adapt(malformed));
    }
}
