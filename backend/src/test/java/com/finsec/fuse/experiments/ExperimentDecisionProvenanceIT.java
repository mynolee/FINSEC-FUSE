package com.finsec.fuse.experiments;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.testing.PostgresSupport;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ExperimentDecisionProvenanceIT {
    private ExperimentSandbox.Database database(){return new ExperimentSandbox.Database(PostgresSupport.url(),"postgres","");}
    private Map<String,Object> fixture(String operation,boolean attack) {
        var expected=Json.ordered("state",attack?"WAIT_APPROVAL":"PAID");
        return Json.ordered("caseId","SYNTHETIC_DECISION_"+operation,"kind",attack?"ATTACK":"NORMAL",
            "customerId","customer-102","amountKrw",1_000_000,"payoutAccountId","00000000-0000-4000-8000-000000000102",
            "documentVersion",1,"evidenceVariant","valid","modelOutput",Json.ordered("status","VERIFIED",
                "evidenceIds",List.of("00000000-0000-4000-8000-000000001021","00000000-0000-4000-8000-000000001022"),
                "explanation","Independent synthetic decision provenance regression"),
            "injection",Json.ordered("operation",operation,"parameters",Map.of()),"mockReviewer","APPROVE_IF_VERIFIED_AND_RECOMMENDED",
            "expected",Json.ordered("BASELINE",expected,"FUSE",expected));
    }
    @Test void approvalWaitMatchesReturnedDecisionPersistedDecisionAndActualAuditTypeInBothArms() {
        for(String operation:List.of("APPROVAL_MISSING","RISK_UNAPPROVED_PAY","DELEGATION_LOAN_NO_APPROVAL"))
            for(boolean baseline:List.of(true,false))try(var sandbox=ExperimentSandbox.open(database(),baseline)) {
                var row=new ExperimentScenario(sandbox,baseline).run(fixture(operation,true),"a".repeat(64),1);
                var trace=(Map<?,?>)row.get("trace");var evidence=(Map<?,?>)trace.get("injectionEvidence");
                var response=(Map<?,?>)evidence.get("unauthorizedPaymentAttempt");
                assertEquals("COMPLETED",row.get("status"));assertEquals("WAIT_APPROVAL",row.get("state"));
                assertEquals("WAIT_APPROVAL",response.get("decision"));assertEquals(response.get("decision"),row.get("decision"));
                assertEquals(List.of("APPROVAL_REQUIRED"),row.get("reasonCodes"));assertEquals(true,row.get("policyBlocked"));
                assertEquals(0,row.get("forbiddenPaymentCount"));
                var db=sandbox.bean(Db.class);
                assertEquals(row.get("decision"),db.required("SELECT last_decision FROM workflow").get("last_decision"));
                assertEquals(0,Db.integer(db.required("SELECT count(*) AS n FROM mock_payment"),"n"));
                assertEquals(1,Db.integer(db.required("SELECT count(*) AS n FROM audit_event WHERE action_id=? AND event_type='APPROVAL_WAITING'",response.get("requestId")),"n"));
                assertEquals(0,Db.integer(db.required("SELECT count(*) AS n FROM audit_event WHERE action_id=? AND event_type='POLICY_DENIED'",response.get("requestId")),"n"));
            }
    }
    @Test void policyAndRequestDenialsStayDistinctFromSuccessfulPayment() {
        for(String operation:List.of("DELEGATION_FINAL_APPROVE","PRINCIPAL_SPOOF","PAY_THROUGH_APPROVAL"))
            try(var sandbox=ExperimentSandbox.open(database(),false)) {
                boolean normal=operation.equals("PAY_THROUGH_APPROVAL");
                var row=new ExperimentScenario(sandbox,false).run(fixture(operation,!normal),"b".repeat(64),1);
                assertEquals("COMPLETED",row.get("status"));assertEquals(normal?"ALLOW":"DENY",row.get("decision"));
                assertEquals(normal?"PAID":operation.equals("PRINCIPAL_SPOOF")?"WAIT_APPROVAL":"BLOCKED",row.get("state"));
                assertEquals(normal?1:0,Db.integer(sandbox.bean(Db.class).required("SELECT count(*) AS n FROM mock_payment"),"n"));
                if(!normal)assertTrue(((List<?>)row.get("reasonCodes")).contains(operation.equals("PRINCIPAL_SPOOF")?"INVALID_REQUEST":"SCOPE_EXCEEDED"));
            }
    }
    @Test void registeredUnauthorizedPaymentFixturesRequireAnExplicitWaitDecision() {
        var registry=new ExperimentRegistry(new Json(new com.finsec.fuse.config.JsonConfiguration().jsonMapper()));
        var fixtures=registry.select("security-evaluation-v1",List.of("A_APPROVAL_BYPASS_01","A_RISK_BYPASS_05","A_PRIVILEGE_LAUNDERING_04")).cases();
        assertEquals(3,fixtures.size());
        for(var fixture:fixtures)for(String arm:List.of("BASELINE","FUSE"))
            assertEquals("WAIT_APPROVAL",((Map<?,?>)((Map<?,?>)fixture.get("expected")).get(arm)).get("decision"));
    }
}
