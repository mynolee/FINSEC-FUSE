package com.finsec.fuse.integration;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.policy.EvidenceChecks;
import com.finsec.fuse.policy.EvidenceRecord;
import com.finsec.fuse.workflow.KycContract;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Synthetic, correctly bound service responses against real PostgreSQL registry rows.
 * A_EVIDENCE_03/A_EVIDENCE_04 cover KYC completion only, not the full revoked/expired
 * phase matrix, live-model robustness, or deployed-clock calibration.
 */
class AuthenticEvidenceRejectionIT extends PaymentFixture {
    @Autowired FusePolicy policy;
    private static final String CUSTOMER="customer-101";

    @ParameterizedTest
    @CsvSource({"FAIL,ID_DOC","FAIL,FACE_MATCH","EXPIRED,ID_DOC","EXPIRED,FACE_MATCH"})
    void falseVerifiedCommitsEvidenceDenialAndLeavesNormalCustomerUnaffected(String defect,String kind) {
        var ids=issueEvidence101();
        assertPairValid(ids,clock.now());
        mutateAuthenticEvidence(kind,defect);
        assertOnlySelectedPredicateFails(ids,kind,defect);
        Instant unchangedTime=clock.now();
        UUID workflowId=start(CUSTOMER);
        var prepared=prepareKyc();
        assertReachableBoundInput(prepared,ids);
        var response=verified(prepared);
        assertTrue(response.boundTo(prepared.input()));
        var lineageBefore=lineage(prepared.input().runId());
        var riskBefore=rows("risk_ledger",workflowId);
        var auditBefore=rows("audit_event",workflowId);
        byte[] inputBefore=(byte[])db.required("select input_bytes from agent_run where id=?",prepared.input().runId()).get("input_bytes");
        var evidenceBefore=db.query("select row_to_json(t)::text body from trusted_evidence t where customer_id=? order by id",CUSTOMER);

        // apply returns normally; assertions run after its transaction has committed.
        assertDoesNotThrow(()->kyc.apply(prepared,response));

        assertEquals(unchangedTime,clock.now(),"Evidence was expired before preparation; no job clock advance");
        assertBlocked(workflowId,prepared);
        assertEquals(lineageBefore,lineage(prepared.input().runId()));
        assertEquals(prepared.input().inputSnapshotHash(),str(db.required("select input_snapshot_hash from agent_run where id=?",prepared.input().runId()),"input_snapshot_hash"));
        assertPreservedProposal(prepared,response,"INVALIDATED");
        assertArrayEquals(inputBefore,(byte[])db.required("select input_bytes from agent_run where id=?",prepared.input().runId()).get("input_bytes"));
        assertEquals(evidenceBefore,db.query("select row_to_json(t)::text body from trusted_evidence t where customer_id=? order by id",CUSTOMER));
        assertEquals(riskBefore,rows("risk_ledger",workflowId));
        assertTrue(rows("audit_event",workflowId).containsAll(auditBefore),"Prior history remains append-only");
        assertEquals(1,queryCount("select count(*) n from audit_event where workflow_id=? and event_type='KYC_PROPOSED'",workflowId));
        assertEquals(1,queryCount("select count(*) n from audit_event where workflow_id=? and event_type='QUARANTINE_APPLIED' and reason_code='EVIDENCE_INVALID'",workflowId));
        assertEquals(0,queryCount("select count(*) n from audit_event where workflow_id=? and event_type in ('LATE_RESULT_DISCARDED','EVIDENCE_VALIDATED','PAYMENT_COMMITTED')",workflowId));
        assertTrue(jobs.claim().isEmpty());

        // A RUN quarantine must not prevent another customer's complete mock workflow.
        var blockedHistory=rows("audit_event",workflowId);
        UUID normal=ready102();
        var pay=approve(normal);
        paymentAgent.execute(pay.jobId(),pay.token());
        assertEquals("PAID",str(workflow(normal),"state"));
        assertRisk(normal,85,0);
        assertEquals(1,queryCount("select count(*) n from mock_payment where workflow_id=?",normal));
        assertEquals(1,count("mock_payment"));
        assertEquals(1,count("quarantine"));
        assertEquals(blockedHistory,rows("audit_event",workflowId));
        assertBlocked(workflowId,prepared);
        assertEquals(lineageBefore,lineage(prepared.input().runId()));
        assertEquals(prepared.input().inputSnapshotHash(),str(db.required("select input_snapshot_hash from agent_run where id=?",prepared.input().runId()),"input_snapshot_hash"));
        assertPreservedProposal(prepared,response,"INVALIDATED");
        assertTrue(jobs.claim().isEmpty());
    }

    @ParameterizedTest @ValueSource(strings={"ID_DOC","FACE_MATCH"})
    void honestNotVerifiedWithAuthenticFailIsBusinessRejectionWithoutAttackQuarantine(String kind) {
        var ids=issueEvidence101();
        mutateAuthenticEvidence(kind,"FAIL");
        assertOnlySelectedPredicateFails(ids,kind,"FAIL");
        UUID workflowId=start(CUSTOMER);
        var prepared=prepareKyc();
        assertReachableBoundInput(prepared,ids);
        var i=prepared.input();
        var response=new KycContract.Response(i.requestId(),i.workflowId(),i.generation(),i.runId(),i.inputSnapshotHash(),
                new KycContract.Proposal(KycContract.ProposalStatus.NOT_VERIFIED,ids,"Synthetic honest failure control"),
                new KycContract.ModelMetadata("replay","KYC-PROMPT-1"));
        assertTrue(response.boundTo(i));
        assertDoesNotThrow(()->kyc.apply(prepared,response));
        assertEquals("REJECTED",str(workflow(workflowId),"state"));
        assertEquals("ALLOW",str(workflow(workflowId),"last_decision"));
        assertEquals("IDENTITY_CHECK_FAILED",str(workflow(workflowId),"last_reason_code"));
        assertRisk(workflowId,10,0);
        assertEquals(0,count("quarantine"));
        assertEquals("FAILED",str(db.required("select status from agent_run where id=?",i.runId()),"status"));
        assertEquals("SUCCEEDED",str(db.required("select state from workflow_job where id=?",prepared.jobId()),"state"));
        assertPreservedProposal(prepared,response,"PROPOSED");
        assertNoDownstream(workflowId);
        assertEquals(1,queryCount("select count(*) n from audit_event where workflow_id=? and event_type='KYC_REVIEW_COMPLETED' and reason_code='IDENTITY_CHECK_FAILED'",workflowId));
        assertTrue(jobs.claim().isEmpty());
    }

    private void mutateAuthenticEvidence(String kind,String defect) {
        var row=db.required("select * from trusted_evidence where customer_id=? and evidence_type=?",CUSTOMER,kind);
        String outcome=defect.equals("FAIL")?"FAIL":"PASS";
        Instant issued=defect.equals("EXPIRED")?clock.now().minusSeconds(120):instant(row,"issued_at");
        Instant expires=defect.equals("EXPIRED")?clock.now().minusSeconds(1):instant(row,"expires_at");
        var original=Json.ordered("customerId",CUSTOMER,"evidenceType",kind,"issuerId",str(row,"issuer_id"),
                "outcome",outcome,"issuedAt",issued.toString(),"expiresAt",expires.toString());
        tx.executeWithoutResult(status->{db.gate();
            assertEquals(1,db.update("update trusted_evidence set outcome=?,issued_at=?,expires_at=?,original_json=?,original_hash=? where id=?",
                    outcome,issued,expires,json.write(original),json.hash(original),uuid(row,"id")));
        });
    }

    private EvidenceChecks checks() {return new EvidenceChecks(policy.trustedIssuers(),json);}

    private Map<UUID,EvidenceRecord> registry() {
        var result=new LinkedHashMap<UUID,EvidenceRecord>();
        for(var row:db.query("select * from trusted_evidence where customer_id=? order by id",CUSTOMER)) {
            var e=new EvidenceRecord(uuid(row,"id"),str(row,"customer_id"),str(row,"evidence_type"),str(row,"issuer_id"),
                    integer(row,"version"),str(row,"outcome"),str(row,"status"),instant(row,"issued_at"),instant(row,"expires_at"),
                    instant(row,"revoked_at"),json.map(str(row,"original_json")),str(row,"original_hash"));
            assertEquals(CUSTOMER,e.customerId());
            assertEquals("ACTIVE",e.status());assertNull(e.revokedAt());assertEquals(1,e.version());
            assertTrue(policy.trustedIssuers().get(e.evidenceType()).contains(e.issuerId()));
            assertEquals(checks().canonicalOriginal(e),e.original());
            assertEquals(json.hash(checks().canonicalOriginal(e)),e.originalHash());
            assertTrue(e.issuedAt().isBefore(e.expiresAt()));
            result.put(e.id(),e);
        }
        return result;
    }

    private void assertPairValid(List<UUID> ids,Instant time) {
        assertTrue(checks().evaluate("VERIFIED",ids,Set.copyOf(ids),registry(),CUSTOMER,time).validated());
    }

    private void assertOnlySelectedPredicateFails(List<UUID> ids,String kind,String defect) {
        var records=registry();
        assertEquals(Set.copyOf(ids),records.keySet());
        assertEquals(Set.of("ID_DOC","FACE_MATCH"),new HashSet<>(records.values().stream().map(EvidenceRecord::evidenceType).toList()));
        for(var e:records.values()) {
            assertFalse(clock.now().isBefore(e.issuedAt()));
            if(defect.equals("EXPIRED") && kind.equals(e.evidenceType()))assertTrue(e.expiresAt().isBefore(clock.now()));
            else assertTrue(clock.now().isBefore(e.expiresAt()));
            assertEquals(defect.equals("FAIL") && kind.equals(e.evidenceType())?"FAIL":"PASS",e.outcome());
        }
        var denied=checks().evaluate("VERIFIED",ids,Set.copyOf(ids),records,CUSTOMER,clock.now());
        assertEquals("EVIDENCE_INVALID",denied.reasonCode());assertTrue(denied.securityViolation());
        if(defect.equals("EXPIRED")) {
            // Counterfactual immediately before expiry proves every other authenticity predicate.
            assertPairValid(ids,clock.now().minusSeconds(2));
        } else {
            var honest=checks().evaluate("NOT_VERIFIED",ids,Set.copyOf(ids),records,CUSTOMER,clock.now());
            assertEquals("REJECTED",honest.state());assertFalse(honest.securityViolation());
        }
    }

    private void assertReachableBoundInput(KycContract.Prepared p,List<UUID> ids) {
        assertEquals(CUSTOMER,p.input().customerId());
        assertEquals(Set.copyOf(ids),new HashSet<>(p.input().evidenceFacts().stream().map(KycContract.EvidenceFact::evidenceId).toList()));
        assertEquals(2,p.input().evidenceFacts().size());
        assertEquals(Set.copyOf(ids),new HashSet<>(db.query("select evidence_id from run_evidence_use where run_id=?",p.input().runId()).stream().map(r->uuid(r,"evidence_id")).toList()));
        assertEquals(json.hash(p.input().unhashed()),p.input().inputSnapshotHash());
        assertTrue(clock.now().isBefore(instant(db.required("select lease_until from workflow_job where id=?",p.jobId()),"lease_until")));
    }

    private void assertBlocked(UUID workflowId,KycContract.Prepared p) {
        var w=workflow(workflowId);
        assertEquals("BLOCKED",str(w,"state"));assertEquals("DENY",str(w,"last_decision"));
        assertEquals("EVIDENCE_INVALID",str(w,"last_reason_code"));assertRisk(workflowId,10,0);
        var q=db.required("select * from quarantine where run_id=?",p.input().runId());
        assertEquals("RUN",str(q,"scope"));assertEquals("ACTIVE",str(q,"status"));assertEquals("EVIDENCE_INVALID",str(q,"reason_code"));
        assertEquals("BLOCKED",str(db.required("select status from agent_run where id=?",p.input().runId()),"status"));
        var job=db.required("select * from workflow_job where id=?",p.jobId());
        assertEquals("FAILED",str(job,"state"));assertEquals("QUARANTINED",str(job,"last_error"));
        assertNoDownstream(workflowId);
    }

    private void assertPreservedProposal(KycContract.Prepared p,KycContract.Response response,String status) {
        var result=db.required("select * from agent_result where run_id=?",p.input().runId());
        assertEquals(1,queryCount("select count(*) n from agent_result where run_id=?",p.input().runId()));
        assertEquals(status,str(result,"status"));assertNull(result.get("evidence_bundle_hash"));
        assertEquals(p.input().workflowId(),uuid(result,"workflow_id"));assertEquals(p.input().generation(),integer(result,"generation"));
        var body=Json.ordered("status",response.proposal().status().name(),"evidenceIds",response.proposal().evidenceIds(),
                "explanation",response.proposal().explanation(),"modelMetadata",response.modelMetadata());
        assertEquals(json.map(json.write(body)),json.map(str(result,"body_json")));
        assertEquals(json.hash(body),str(result,"result_hash"));
    }

    private void assertNoDownstream(UUID workflowId) {
        assertNull(workflow(workflowId).get("current_kyc_result_id"));
        assertNull(workflow(workflowId).get("current_loan_result_id"));
        assertEquals(0,queryCount("select count(*) n from agent_result where workflow_id=? and status='VALIDATED'",workflowId));
        assertEquals(0,queryCount("select count(*) n from agent_run where workflow_id=? and role in ('LOAN','PAYMENT')",workflowId));
        assertEquals(0,queryCount("select count(*) n from workflow_job where workflow_id=? and phase in ('LOAN','PAY')",workflowId));
        for(String table:List.of("approval","payment_reservation","mock_payment"))
            assertEquals(0,queryCount("select count(*) n from "+table+" where workflow_id=?",workflowId));
    }

    private Map<String,List<Map<String,Object>>> lineage(UUID runId) {
        var result=new LinkedHashMap<String,List<Map<String,Object>>>();
        for(String table:List.of("run_source_use","run_evidence_use"))
            result.put(table,db.query("select row_to_json(t)::text body from "+table+" t where run_id=? order by row_to_json(t)::text",runId));
        return result;
    }

    private long queryCount(String sql,UUID id) {return number(db.required(sql,id),"n");}
    private List<Map<String,Object>> rows(String table,UUID workflowId) {
        return db.query("select row_to_json(t)::text body from "+table+" t where workflow_id=? order by id",workflowId);
    }
}
