package com.finsec.fuse.quarantine;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.payment.PaymentFixture;
import java.util.*;
import org.junit.jupiter.api.Test;

class SecurityScopeIT extends PaymentFixture {
    private static final Actor SCOPED=new Actor("restricted-security","SECURITY_OPERATOR",Set.of("customer-101"));
    @Test void securityRoleCannotApplyReadOrReleaseAnotherCustomersQuarantine() {
        UUID workflowId=ready102();UUID run=kycRun(workflowId);
        var request=new QuarantineRequest(QuarantineRequest.Scope.RUN,run,null,null,null,null,null,null,QuarantineRequest.Reason.SECURITY_INVESTIGATION,"Outside assigned scope");
        assertForbidden(()->quarantines.apply(SCOPED,UUID.randomUUID(),request));
        assertEquals(0,count("quarantine"));assertEquals("WAIT_APPROVAL",str(workflow(workflowId),"state"));
        var incident=quarantines.apply(SECURITY,UUID.randomUUID(),request);UUID quarantineId=(UUID)incident.get("quarantineId");
        assertForbidden(()->quarantines.impact(SCOPED,quarantineId));
        var ids=db.query("select id from trusted_evidence where customer_id='customer-102'").stream().map(r->uuid(r,"id")).toList();
        assertForbidden(()->quarantines.release(SCOPED,quarantineId,UUID.randomUUID(),new ReleaseRequest(new ReleaseRequest.Remediation(DOCUMENT,1,ids,null,null,"Unauthorized clearance"))));
        assertEquals("ACTIVE",str(db.required("select * from quarantine where id=?",quarantineId),"status"));
        assertForbidden(()->quarantines.impact(SCOPED,UUID.randomUUID()));
    }
    @Test void sourceAndAgentVersionScopesRequireEveryRegisteredPotentialCustomer() {
        UUID workflowId=start("customer-101");prepareKyc();
        // The safe document has registered consumers 102–104 even before their runs exist.
        assertForbidden(()->quarantines.apply(SCOPED,UUID.randomUUID(),new QuarantineRequest(QuarantineRequest.Scope.SOURCE_VERSION,null,null,null,DOCUMENT,1,null,null,QuarantineRequest.Reason.SOURCE_COMPROMISED,"Would affect unassigned customers")));
        assertForbidden(()->quarantines.apply(SCOPED,UUID.randomUUID(),new QuarantineRequest(QuarantineRequest.Scope.AGENT_VERSION,null,null,null,null,null,"KYC",1,QuarantineRequest.Reason.AGENT_COMPROMISED,"Would affect all customers")));
        var allowed=quarantines.apply(SCOPED,UUID.randomUUID(),new QuarantineRequest(QuarantineRequest.Scope.RUN,kycRun(workflowId),null,null,null,null,null,null,QuarantineRequest.Reason.SECURITY_INVESTIGATION,"Assigned customer only"));
        assertEquals("ACTIVE",allowed.get("state"));assertEquals(1,count("quarantine"));
    }
    @Test void previouslyAuthorizedReplayCannotDiscloseARestrictedIncidentAfterScopeChanges() {
        UUID workflowId=ready102();UUID action=UUID.randomUUID();
        var request=new QuarantineRequest(QuarantineRequest.Scope.WORKFLOW,null,null,workflowId,null,null,null,null,QuarantineRequest.Reason.SECURITY_INVESTIGATION,"Scope may narrow later");
        quarantines.apply(SECURITY,action,request);
        Actor narrowed=new Actor(SECURITY.actorId(),SECURITY.role(),Set.of("customer-101"));
        assertForbidden(()->quarantines.apply(narrowed,action,request));assertEquals(1,count("quarantine"));
    }
    @Test void releasedRecoverySourceRequiresReplacementCustomerScopeBeforeResume() {
        UUID workflowId=prepareReleasedRecovery101();
        assertEquals("BLOCKED",str(workflow(workflowId),"state"));
        assertRecoverySourceDenialPreservesDatabase();
        recovery.resume(REVIEWER,workflowId,UUID.randomUUID(),new ResumeRequest(1,"Reviewed recovery source"));
        assertRecoveredSourceCanBePrepared(workflowId);
    }
    @Test void resumedRecoverySourceRequiresReplacementCustomerScopeBeforePrepare() {
        UUID workflowId=prepareReleasedRecovery101();
        recovery.resume(REVIEWER,workflowId,UUID.randomUUID(),new ResumeRequest(1,"Reviewed recovery source"));
        assertEquals("KYC_PENDING",str(workflow(workflowId),"state"));
        assertEquals(2,integer(workflow(workflowId),"generation"));
        assertRecoverySourceDenialPreservesDatabase();
        assertRecoveredSourceCanBePrepared(workflowId);
    }
    @Test void fullScopeRecoverySourceQuarantineDoesNotInventActualConsumption() {
        UUID workflowId=prepareReleasedRecovery101();
        recovery.resume(REVIEWER,workflowId,UUID.randomUUID(),new ResumeRequest(1,"Reviewed recovery source"));
        var before=workflow(workflowId);
        var result=quarantines.apply(SECURITY,UUID.randomUUID(),safeSourceRequest());
        assertEquals("ACTIVE",result.get("state"));
        var impact=quarantines.impact(SECURITY,(UUID)result.get("quarantineId"));
        var actual=(Map<?,?>)impact.get("actual");
        for(String key:List.of("runCount","roleCount","workflowCount","customerCount","paymentCount","paidAmountKrw","atRiskPendingAmountKrw"))
            assertEquals(0L,((Number)actual.get(key)).longValue(),key);
        for(String key:List.of("historicalRunIds","currentAffectedWorkflowIds","policyHeldWorkflowIds","nodes","edges"))
            assertTrue(((Collection<?>)impact.get(key)).isEmpty(),key);
        var potential=(Map<?,?>)impact.get("potential");
        assertEquals(0L,((Number)potential.get("applicationCount")).longValue());
        assertEquals("0",potential.get("totalAmountKrw"));
        assertEquals(before,workflow(workflowId));
        assertEquals(0,count("agent_run"));assertEquals(0,count("run_source_use"));
        assertEquals(0,count("risk_ledger"));assertEquals(0,count("mock_payment"));assertRisk(workflowId,0,0);
    }
    private UUID prepareReleasedRecovery101() {
        UUID workflowId=start("customer-101");
        var incident=quarantines.apply(SECURITY,UUID.randomUUID(),new QuarantineRequest(QuarantineRequest.Scope.WORKFLOW,null,null,workflowId,null,null,null,null,QuarantineRequest.Reason.SECURITY_INVESTIGATION,"Synthetic recovery scope fixture"));
        // Authorized fixture provisioning models independent remediation, never an attacker capability.
        var evidenceIds=issueEvidence101();
        quarantines.release(SECURITY,(UUID)incident.get("quarantineId"),UUID.randomUUID(),new ReleaseRequest(new ReleaseRequest.Remediation(DOCUMENT,1,evidenceIds,null,null,"Independently reviewed fixture remediation")));
        assertEquals(DOCUMENT,uuid(workflow(workflowId),"recovery_document_id"));
        assertEquals(1,integer(workflow(workflowId),"recovery_document_version"));
        assertEquals(0,count("agent_run"));assertEquals(0,count("run_source_use"));
        assertEquals(0,integer(db.required("select * from workflow_stage where workflow_id=? and stage='KYC'",workflowId),"run_count"));
        assertRisk(workflowId,0,0);
        return workflowId;
    }
    private void assertRecoverySourceDenialPreservesDatabase() {
        Actor originalsOnly=new Actor("original-source-security","SECURITY_OPERATOR",Set.of("customer-102","customer-103","customer-104"));
        var before=snapshotDatabase();
        assertForbidden(()->quarantines.apply(originalsOnly,UUID.randomUUID(),safeSourceRequest()));
        assertEquals(before,snapshotDatabase(),"Forbidden source quarantine must leave all durable business rows, actions, audits and gate epoch unchanged");
    }
    private void assertRecoveredSourceCanBePrepared(UUID workflowId) {
        var prepared=prepareKyc();
        assertEquals(workflowId,prepared.input().workflowId());assertEquals(2,prepared.input().generation());
        assertEquals(DOCUMENT,prepared.input().documents().getFirst().documentId());
        assertEquals(1,prepared.input().documents().getFirst().documentVersion());
        assertEquals(1,count("agent_run"));assertEquals(1,count("run_source_use"));assertRisk(workflowId,10,0);
    }
    private Map<String,List<String>> snapshotDatabase() {
        var rows=new TreeMap<String,List<String>>();
        for(String table:db.jdbc().queryForList("select table_name from information_schema.tables where table_schema='public' and table_type='BASE TABLE' order by table_name",String.class))
            rows.put(table,db.jdbc().queryForList("select to_jsonb(t)::text from public.\""+table.replace("\"","\"\"")+"\" t order by to_jsonb(t)::text",String.class));
        return rows;
    }
    private static QuarantineRequest safeSourceRequest() {
        return new QuarantineRequest(QuarantineRequest.Scope.SOURCE_VERSION,null,null,null,DOCUMENT,1,null,null,QuarantineRequest.Reason.SOURCE_COMPROMISED,"Synthetic replacement source scope check");
    }
    private static void assertForbidden(Runnable action) {var ex=assertThrows(ApiException.class,action::run);assertEquals(403,ex.status());assertEquals("FORBIDDEN",ex.reasonCode());}
}
