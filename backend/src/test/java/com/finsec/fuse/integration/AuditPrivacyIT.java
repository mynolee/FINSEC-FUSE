package com.finsec.fuse.integration;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;

import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.payment.*;
import com.finsec.fuse.quarantine.*;
import com.finsec.fuse.workflow.StartWorkflowRequest;
import com.finsec.fuse.workflow.WorkflowQueryService;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;

/** Synthetic text only. Covers persisted audit and query projection, not container log collection. */
class AuditPrivacyIT extends PaymentFixture {
    @Autowired WorkflowQueryService queries;
    @Autowired PaymentSupport support;
    private static final List<String> MARKERS=List.of("SYNTHETIC_SIGNING_KEY", "SYNTHETIC_BEARER",
        "SYNTHETIC_SERVICE_TOKEN", "SYNTHETIC_DB_PASSWORD", "SYNTHETIC_ID_DOCUMENT", "SYNTHETIC_FACE");
    private static final String FORGED="SYNTHETIC_FORGED_AUDIT_EVENT";
    private static String privateText() {return String.join("|",MARKERS)+"\r\n"+FORGED+"\n\t";}

    @Test @Timeout(30)
    void unregisteredBusinessReferenceCannotCreateAuditOrActionReceipt() {
        String reference="SYNTHETIC_REFERENCE\r\n"+FORGED;
        var customer=new Actor("customer-102","CUSTOMER",Set.of("customer-102"));
        var request=new StartWorkflowRequest(reference,"customer-102",1000000L,
            UUID.fromString("00000000-0000-4000-8000-000000000102"));
        UUID action=UUID.randomUUID();
        assertTrue(reference.length()<=80);
        assertTrue(db.one("SELECT business_reference FROM application_registry WHERE business_reference=?",reference).isEmpty());
        var before=durableRows();

        var rejected=assertThrows(ApiException.class,()->workflows.start(customer,action,request));

        assertEquals(409,rejected.status());assertEquals("APPLICATION_CONFLICT",rejected.reasonCode());
        assertTrue(db.one("SELECT action_id FROM action_request WHERE action_id=?",action).isEmpty());
        assertTrue(db.query("SELECT id FROM audit_event WHERE action_id=?",action).isEmpty());
        assertEquals(before,durableRows(),"Registry rejection must leave all observed durable rows unchanged");
    }

    @Test @Timeout(30)
    void registeredBusinessReferenceIsOneJsonFieldNotAnExtraAuditEvent() {
        String reference="SYNTHETIC_REFERENCE\r\n"+FORGED;
        var customer=new Actor("customer-102","CUSTOMER",Set.of("customer-102"));
        var request=new StartWorkflowRequest(reference,"customer-102",1000000L,
            UUID.fromString("00000000-0000-4000-8000-000000000102"));
        assertTrue(reference.length()<=80);
        // Test-only registration: public workflow input cannot create this registry entry.
        tx.executeWithoutResult(status->{db.gate();assertEquals(1,db.update(
            "INSERT INTO application_registry(business_reference,customer_id,amount_krw,payout_account_id,document_id,document_version) "+
            "SELECT ?,customer_id,amount_krw,payout_account_id,document_id,document_version FROM application_registry WHERE business_reference='APP-DEMO-102-001'",reference));});
        var before=durableRows();UUID action=UUID.randomUUID();

        var accepted=workflows.start(customer,action,request);

        UUID workflowId=(UUID)accepted.get("workflowId");
        assertEquals("KYC_PENDING",accepted.get("state"));assertEquals(false,accepted.get("replayed"));
        var created=db.required("SELECT * FROM audit_event WHERE action_id=?",action);
        assertInstanceOf(UUID.class,created.get("id"));assertEquals(workflowId,created.get("workflow_id"));
        assertEquals(customer.actorId(),created.get("actor_id"));assertEquals("WORKFLOW_CREATED",created.get("event_type"));
        var details=auditDetails(action,"WORKFLOW_CREATED");
        assertEquals(Set.of("jobId","businessReference"),details.keySet());
        assertEquals(reference,details.get("businessReference"));
        UUID jobId=UUID.fromString((String)details.get("jobId"));
        assertEquals(workflowId,db.required("SELECT workflow_id FROM workflow_job WHERE id=?",jobId).get("workflow_id"));
        assertEquals(reference,db.required("SELECT business_reference FROM loan_application WHERE id=?",
            workflow(workflowId).get("application_id")).get("business_reference"));
        String storedJson=str(created,"details_json");
        assertFalse(storedJson.contains("\r"));assertFalse(storedJson.contains("\n"));
        assertEquals(details,json.map(storedJson));

        var after=durableRows();
        var expectedAdds=Map.of("loan_application",1,"workflow",1,"workflow_stage",3,"workflow_job",1,"audit_event",1,"action_request",1);
        before.forEach((table,rows)->{
            assertEquals(rows.size()+expectedAdds.getOrDefault(table,0),after.get(table).size(),table+" record count");
            assertTrue(after.get(table).containsAll(rows),table+" existing rows must remain unchanged");
        });
        assertTrue(db.query("SELECT id FROM audit_event WHERE event_type=?",FORGED).isEmpty());
        var receipt=json.map(str(db.required("SELECT result_json FROM action_request WHERE action_id=?",action),"result_json"));
        assertEquals(workflowId.toString(),receipt.get("workflowId"));assertEquals(action.toString(),receipt.get("requestId"));

        // Authorized operational projections retain registered business data; they are not sanitized exports.
        var trace=queries.trace(REVIEWER,workflowId);
        assertEquals(1,((List<?>)trace.get("auditEvents")).size());
        assertEquals(details,traceDetails(trace,action));
        String traceJson=json.write(trace);
        assertFalse(traceJson.contains("\r"));assertFalse(traceJson.contains("\n"));
        assertEquals(1,((List<?>)json.map(traceJson).get("auditEvents")).size());
        var customerDetail=queries.detail(customer,workflowId);
        assertEquals(reference,json.map(json.write(customerDetail)).get("businessReference"));
        assertEquals(403,assertThrows(ApiException.class,()->queries.trace(customer,workflowId)).status());
        assertEquals(true,workflows.start(customer,action,request).get("replayed"));
        assertEquals(after,durableRows(),"Reads and exact replay must not append events or receipts");
    }

    @Test @Timeout(30)
    void releaseAndResumeAuditOnlyCheckedFieldsWhileOriginalBodiesStillBindReplay() {
        UUID workflowId=start("customer-102");var prepared=prepareKyc();
        UUID quarantineAction=UUID.randomUUID();
        var blocked=quarantines.apply(SECURITY,quarantineAction,new QuarantineRequest(QuarantineRequest.Scope.RUN,
            prepared.input().runId(),null,null,null,null,null,null,
            QuarantineRequest.Reason.SECURITY_INVESTIGATION,privateText()));
        UUID incident=(UUID)blocked.get("quarantineId");
        assertEquals(privateText(),db.required("SELECT note FROM quarantine WHERE id=?",incident).get("note"));
        assertEquals("BLOCKED",workflow(workflowId).get("state"));assertRisk(workflowId,10,0);
        var evidenceIds=db.query("SELECT id FROM trusted_evidence WHERE customer_id='customer-102' ORDER BY id")
            .stream().map(row->uuid(row,"id")).toList();
        // A replacement agent is irrelevant to a RUN release and must not become audit authority.
        var remediation=new ReleaseRequest.Remediation(DOCUMENT,1,evidenceIds,"SYNTHETIC_UNUSED_AGENT",99,privateText());
        var releaseRequest=new ReleaseRequest(remediation);UUID releaseAction=UUID.randomUUID();
        var released=quarantines.release(SECURITY,incident,releaseAction,releaseRequest);
        assertEquals("RELEASED",db.required("SELECT status FROM quarantine WHERE id=?",incident).get("status"));
        var storedRemediation=json.map(str(db.required("SELECT remediation_json FROM quarantine WHERE id=?",incident),"remediation_json"));
        assertEquals(privateText(),storedRemediation.get("note"));
        var checked=auditDetails(releaseAction,"RECOVERY_CHECKED");
        assertEquals(Set.of("safeDocumentId","safeDocumentVersion","checks","noteProvided"),checked.keySet());
        assertEquals(DOCUMENT.toString(),checked.get("safeDocumentId"));assertEquals(1,checked.get("safeDocumentVersion"));
        assertEquals(true,checked.get("noteProvided"));assertEquals(1,((List<?>)checked.get("checks")).size());
        assertFalse(json.write(checked).contains("SYNTHETIC_UNUSED_AGENT"));

        UUID resumeAction=UUID.randomUUID();var resumeRequest=new ResumeRequest(1,privateText());
        var resumed=recovery.resume(REVIEWER,workflowId,resumeAction,resumeRequest);
        assertEquals("KYC_PENDING",resumed.get("state"));assertEquals("ALLOW",resumed.get("decision"));
        assertEquals(2,integer(workflow(workflowId),"generation"));assertRisk(workflowId,10,0);
        var resumedDetails=auditDetails(resumeAction,"WORKFLOW_RESUMED");
        assertEquals(Set.of("previousGeneration","generation","kycJobId","usedRiskRetained","runCountRetained","reasonProvided"),resumedDetails.keySet());
        assertEquals(true,resumedDetails.get("reasonProvided"));
        assertEquals(1,resumedDetails.get("previousGeneration"));assertEquals(2,resumedDetails.get("generation"));
        assertEquals(1,count("agent_run"));assertEquals(0,count("agent_result"));
        assertEquals(0,count("mock_payment"));assertEquals(1,events("CHARGE"));
        assertNoPrivateText(blocked);assertNoPrivateText(released);assertNoPrivateText(resumed);
        assertNoPrivateText(db.query("SELECT to_jsonb(a)::text AS row_json FROM audit_event a"));
        assertSafeViews(workflowId);

        var beforeReplay=durableRows();
        assertEquals(true,quarantines.release(SECURITY,incident,releaseAction,releaseRequest).get("replayed"));
        assertEquals(true,recovery.resume(REVIEWER,workflowId,resumeAction,resumeRequest).get("replayed"));
        assertEquals(beforeReplay,durableRows());
        var changedResume=assertThrows(ApiException.class,()->recovery.resume(REVIEWER,workflowId,resumeAction,new ResumeRequest(1,"Changed reason")));
        assertEquals("REPLAY_CONFLICT",changedResume.reasonCode());assertEquals(409,changedResume.status());
        var changedRelease=assertThrows(ApiException.class,()->quarantines.release(SECURITY,incident,releaseAction,
            new ReleaseRequest(new ReleaseRequest.Remediation(DOCUMENT,1,evidenceIds,"SYNTHETIC_UNUSED_AGENT",99,"Changed note"))));
        assertEquals("REPLAY_CONFLICT",changedRelease.reasonCode());assertEquals(409,changedRelease.status());
        assertEquals(beforeReplay,durableRows());
    }

    @Test @Timeout(30)
    void literalApprovalCommentAndQuarantineNoteStayOutsideAuditAndTrace() {
        UUID workflowId=ready102();var preview=approvals.preview(REVIEWER,workflowId);
        UUID action=UUID.randomUUID();
        var approved=approvals.decide(REVIEWER,workflowId,action,new ApprovalRequest(ApprovalRequest.Decision.APPROVE,
            (String)preview.get("reviewSnapshotHash"),privateText()));
        assertEquals(privateText(),db.required("SELECT comment FROM approval WHERE workflow_id=?",workflowId).get("comment"));
        var blocked=quarantines.apply(SECURITY,UUID.randomUUID(),new QuarantineRequest(QuarantineRequest.Scope.WORKFLOW,
            null,null,workflowId,null,null,null,null,QuarantineRequest.Reason.SECURITY_INVESTIGATION,privateText()));
        assertEquals(privateText(),db.required("SELECT note FROM quarantine WHERE id=?",blocked.get("quarantineId")).get("note"));
        assertEquals("BLOCKED",workflow(workflowId).get("state"));assertRisk(workflowId,35,0);
        assertEquals(0,count("mock_payment"));assertEquals(0,events("CONSUME"));
        assertNoPrivateText(approved);assertNoPrivateText(blocked);
        assertNoPrivateText(db.query("SELECT to_jsonb(a)::text AS row_json FROM audit_event a"));
        var before=durableRows();assertSafeViews(workflowId);assertEquals(before,durableRows());
    }

    @Test @Timeout(30)
    void legacyAuditProjectionOmitsFreeformTextWithoutRewritingAppendOnlyRows() {
        UUID workflowId=start("customer-102"),jobId=UUID.randomUUID();
        UUID resumeAction=UUID.randomUUID(),releaseAction=UUID.randomUUID();
        // Insert historical-shaped records as an isolated fixture; never update existing audit rows.
        // The second record is workflow-linked so the shared read projection is exercised too.
        tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflowId);
            support.audit(resumeAction,workflowId,null,null,REVIEWER.actorId(),"WORKFLOW_RESUMED",null,
                Json.ordered("previousGeneration",1,"generation",2,"kycJobId",jobId,"usedRiskRetained",10,
                    "runCountRetained",1,"reason",privateText(),"unrecognized",privateText()),clock.now());
            support.audit(releaseAction,workflowId,null,null,SECURITY.actorId(),"RECOVERY_CHECKED",null,
                Json.ordered("safeDocumentId",DOCUMENT,"safeDocumentVersion",1,
                    "checks",List.of(Json.ordered("workflowId",workflowId,"customerId","customer-102",
                        "evidenceBundleHash","a".repeat(64),"unrecognized",privateText())),
                    "remediation",Json.ordered("note",privateText(),"safeAgentId",privateText()),
                    "unrecognized",privateText()),clock.now());
        });
        var before=durableRows();assertTrue(json.write(before).contains(MARKERS.getFirst()));
        var trace=queries.trace(REVIEWER,workflowId);assertNoPrivateText(trace);
        var resumed=traceDetails(trace,resumeAction);
        assertEquals(Set.of("previousGeneration","generation","kycJobId","usedRiskRetained","runCountRetained","reasonProvided"),resumed.keySet());
        assertEquals(jobId.toString(),resumed.get("kycJobId"));assertEquals(true,resumed.get("reasonProvided"));
        var checked=traceDetails(trace,releaseAction);
        assertEquals(Set.of("safeDocumentId","safeDocumentVersion","checks","noteProvided"),checked.keySet());
        assertEquals(true,checked.get("noteProvided"));
        assertEquals(List.of(Map.of("workflowId",workflowId.toString(),"evidenceBundleHash","a".repeat(64))),checked.get("checks"));
        assertSafeViews(workflowId);assertEquals(before,durableRows());
        assertTrue(json.write(auditDetails(resumeAction,"WORKFLOW_RESUMED")).contains(MARKERS.getFirst()));
        assertTrue(json.write(auditDetails(releaseAction,"RECOVERY_CHECKED")).contains(MARKERS.getFirst()));
    }

    private Map<String,Object> auditDetails(UUID action,String event) {
        return json.map(str(db.required("SELECT details_json FROM audit_event WHERE action_id=? AND event_type=?",action,event),"details_json"));
    }
    @SuppressWarnings("unchecked")
    private Map<String,Object> traceDetails(Map<String,Object> trace,UUID action) {
        return (Map<String,Object>)((List<Map<String,Object>>)trace.get("auditEvents")).stream()
            .filter(event->action.equals(event.get("actionId"))).findFirst().orElseThrow().get("detailsJson");
    }
    private void assertSafeViews(UUID workflowId) {
        assertNoPrivateText(queries.trace(REVIEWER,workflowId));
        var customer=new Actor("customer-102","CUSTOMER",Set.of("customer-102"));
        assertNoPrivateText(queries.detail(customer,workflowId));
        assertEquals(403,assertThrows(ApiException.class,()->queries.trace(customer,workflowId)).status());
    }
    private void assertNoPrivateText(Object value) {
        String rendered=json.write(value);
        for(String marker:MARKERS)assertFalse(rendered.contains(marker),"Synthetic private marker escaped its allowed business field");
        assertFalse(rendered.contains(FORGED),"Synthetic event-forging text escaped its allowed business field");
        assertFalse(rendered.contains("\r"));assertFalse(rendered.contains("\n"));
    }
    private Map<String,List<String>> durableRows() {
        var result=new LinkedHashMap<String,List<String>>();
        for(String table:List.of("execution_gate","application_registry","loan_application","workflow","workflow_stage","workflow_job","agent_run","agent_result",
            "delegation_grant","approval","payment_reservation","mock_payment","risk_ledger","quarantine","action_request","audit_event"))
            result.put(table,db.query("SELECT to_jsonb(t)::text AS row_json FROM "+table+" t ORDER BY row_json")
                .stream().map(row->str(row,"row_json")).toList());
        return result;
    }
}
