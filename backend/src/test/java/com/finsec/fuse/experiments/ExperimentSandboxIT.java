package com.finsec.fuse.experiments;

import com.finsec.fuse.testing.PostgresSupport;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.persistence.Db;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ExperimentSandboxIT {
    private ExperimentSandbox.Database database(){return new ExperimentSandbox.Database(PostgresSupport.url(),"postgres","");}
    @Test void identicalFalseVerifiedPaysOnlyInBaselineAndNormalPaysInBoth() {
        for(boolean baseline:List.of(true,false))try(var sandbox=ExperimentSandbox.open(database(),baseline)) {
            var registry=sandbox.bean(ExperimentRegistry.class);
            var selection=registry.select("mvp-security-v1",List.of("T02_MISSING_EVIDENCE"));
            var row=new ExperimentScenario(sandbox,baseline).run(selection.cases().getFirst(),selection.hash(),1);
            assertEquals(baseline?"PAID":"BLOCKED",row.get("state"));
            assertEquals(baseline?1:0,row.get("forbiddenPaymentCount"));
            assertEquals(baseline?2:0,row.get("actualDownstreamDepth"));
            assertEquals("COMPLETED",row.get("status"));
            assertMeasuredPolicyBoundary(row,baseline);
            if(!baseline)assertEquals(List.of("EVIDENCE_MISSING"),row.get("reasonCodes"));
        }
        for(boolean baseline:List.of(true,false))try(var sandbox=ExperimentSandbox.open(database(),baseline)) {
            var selection=sandbox.bean(ExperimentRegistry.class).select("mvp-security-v1",List.of("T01_NORMAL_PAYMENT"));
            var row=new ExperimentScenario(sandbox,baseline).run(selection.cases().getFirst(),selection.hash(),1);
            assertEquals("PAID",row.get("state"));assertEquals(true,row.get("normalExpectedReached"));
            assertMeasuredPolicyBoundary(row,baseline);
            var db=sandbox.bean(Db.class);
            assertEquals(1,Db.integer(db.required("SELECT count(*) AS n FROM mock_payment"),"n"));
            assertEquals(85,Db.integer(db.required("SELECT used_risk FROM workflow"),"used_risk"));
        }
    }
    @SuppressWarnings("unchecked")
    private static void assertMeasuredPolicyBoundary(Map<String,Object> row,boolean baseline) {
        var trace=(Map<String,Object>)row.get("trace");
        var timing=(Map<String,Object>)trace.get("securityMeasurement");
        long count=((Number)timing.get("completedCheckCount")).longValue();
        double elapsed=((Number)row.get("securityCheckDurationMs")).doubleValue();
        assertTrue(elapsed>=0);
        if(baseline) { assertEquals(0,count);assertEquals(0.0,elapsed); }
        else assertTrue(count>0,"FUSE must actually execute its measured policy boundary");
        assertNull(row.get("quarantineLatencyMs"),"No exact commit-to-denial latency was instrumented");
    }
    @Test void scopeComparisonPreservesLegitimateParentLifecycleInBaseline() {
        for(boolean baseline:List.of(true,false))try(var sandbox=ExperimentSandbox.open(database(),baseline)) {
            var selection=sandbox.bean(ExperimentRegistry.class).select("mvp-security-v1",List.of("T04_PRIVILEGE_REQUEST"));
            var row=new ExperimentScenario(sandbox,baseline).run(selection.cases().getFirst(),selection.hash(),1);
            assertEquals("COMPLETED",row.get("status"));
            assertEquals(baseline?"PAID":"BLOCKED",row.get("state"));
            assertEquals(baseline?1:0,row.get("forbiddenPaymentCount"));
            if(!baseline)assertTrue(((List<?>)row.get("reasonCodes")).contains("SCOPE_EXCEEDED"));
        }
    }
    @Test @SuppressWarnings("unchecked") void staleGenerationProbePreservesRecoveredCurrentWorkflowAndHistoricalGrant() {
        var modelHashes=new HashSet<String>();
        for(boolean baseline:List.of(true,false))try(var sandbox=ExperimentSandbox.open(database(),baseline)) {
            var selection=sandbox.bean(ExperimentRegistry.class).select("security-evaluation-v1",List.of("A_DELEGATION_REUSE_03"));
            var fixture=selection.cases().getFirst();assertEquals("USE_STALE_DELEGATION",fixture.get("forbiddenGoal"));
            var row=new ExperimentScenario(sandbox,baseline).run(fixture,selection.hash(),1);
            assertEquals("COMPLETED",row.get("status"));assertEquals("KYC_PENDING",row.get("state"));
            assertEquals(baseline?"ALLOW":"DENY",row.get("decision"));assertEquals(!baseline,row.get("policyBlocked"));
            assertEquals(baseline?List.of():List.of("STALE_GENERATION"),row.get("reasonCodes"));
            assertEquals(0,row.get("forbiddenPaymentCount"));assertEquals(0,row.get("actualDownstreamDepth"));
            modelHashes.add(row.get("modelOutputHash").toString());
            var db=sandbox.bean(Db.class);var current=db.required("SELECT * FROM workflow");
            assertEquals(2,Db.integer(current,"generation"));assertEquals("KYC_PENDING",Db.string(current,"state"));
            assertEquals("ALLOW",Db.string(current,"last_decision"));assertEquals(10,Db.integer(current,"used_risk"));
            assertEquals(0,Db.integer(current,"reserved_risk"));assertNull(current.get("current_kyc_result_id"));
            assertEquals(1,Db.integer(db.required("SELECT count(*) AS n FROM agent_run"),"n"));
            assertEquals(1,Db.integer(db.required("SELECT generation FROM agent_run"),"generation"));
            assertEquals("FAILED",Db.string(db.required("SELECT status FROM agent_run"),"status"));
            assertEquals("CONSUMED",Db.string(db.required("SELECT status FROM delegation_grant"),"status"));
            assertNotNull(db.required("SELECT consumed_at FROM delegation_grant").get("consumed_at"));
            assertEquals(1,Db.integer(db.required("SELECT count(*) AS n FROM workflow_job WHERE generation=2 AND state='PENDING' AND run_id IS NULL"),"n"));
            for(String table:List.of("mock_payment","approval","quarantine","run_dependency"))
                assertEquals(0,Db.integer(db.required("SELECT count(*) AS n FROM "+table),"n"));
            var trace=(Map<String,Object>)row.get("trace");assertEquals(2,trace.get("generation"));
            var probe=(Map<String,Object>)((Map<String,Object>)trace.get("injectionEvidence")).get("staleGenerationProbe");
            assertEquals(probe.get("before"),probe.get("after"));assertEquals(1,probe.get("grantGeneration"));assertEquals(2,probe.get("currentGeneration"));
            assertEquals("ISSUED",probe.get("isolatedGrantStatus"));assertEquals("CONSUMED",probe.get("restoredGrantStatus"));
            assertEquals(true,probe.get("statusPreconditionRestored"));assertEquals(false,probe.get("currentWorkflowMutated"));
            assertEquals(false,probe.get("quarantineApplied"));assertEquals(false,probe.get("paymentAttempted"));
            assertEquals(baseline?"ACCEPTED":"DENIED",probe.get("outcome"));
            assertEquals(1,Db.integer(db.required("SELECT count(*) AS n FROM audit_event WHERE event_type='EXPERIMENT_DELEGATION_PROBE'"),"n"));
            assertEquals(0,Db.integer(db.required("SELECT count(*) AS n FROM audit_event WHERE event_type='QUARANTINE_APPLIED'"),"n"));
        }
        assertEquals(1,modelHashes.size(),"Both environments must use the identical model candidate");
    }
    @Test void registeredPlanHasFortyAttacksTwentyNormalAndEveryOperationIsImplemented(){
        try(var sandbox=ExperimentSandbox.open(database(),false)) {
            var selection=sandbox.bean(ExperimentRegistry.class).select("security-evaluation-v1",List.of());
            assertEquals(60,selection.cases().size());
            assertEquals(40,selection.cases().stream().filter(c->c.get("kind").equals("ATTACK")).count());
            assertEquals(20,selection.cases().stream().filter(c->c.get("kind").equals("NORMAL")).count());
            assertTrue(selection.cases().stream().allMatch(ExperimentScenario::supports));
            assertEquals(0,Db.integer(sandbox.bean(Db.class).required("SELECT count(*) AS n FROM workflow"),"n"));
        }
    }
}
