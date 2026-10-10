package com.finsec.fuse.policy;

import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.quarantine.*;
import com.finsec.fuse.workflow.KycContract;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;

/** Recomputed originals/hashes ensure these failures are issuer authority checks, not digest mismatch. */
class TypedEvidenceIssuerIT extends PaymentFixture {
    @Autowired EvidenceValidator evidence;
    private UUID crossIssue(String customer,String kind,String outcome) {
        var row=db.required("select * from trusted_evidence where customer_id=? and evidence_type=?",customer,kind);
        UUID id=uuid(row,"id");String issuer=kind.equals("ID_DOC")?"mock-face-issuer":"mock-id-issuer";
        var original=new LinkedHashMap<>(json.map(str(row,"original_json")));
        original.put("issuerId",issuer);original.put("outcome",outcome);
        tx.executeWithoutResult(status->{db.gate();db.update("update trusted_evidence set issuer_id=?,outcome=?,original_json=?,original_hash=? where id=?",
                issuer,outcome,json.write(original),json.hash(original),id);});
        return id;
    }
    @ParameterizedTest @ValueSource(strings={"ID_DOC","FACE_MATCH"})
    void crossIssuerVerifiedIsQuarantinedBeforeLoanOrPayment(String kind) {
        crossIssue("customer-102",kind,"PASS");UUID workflowId=start("customer-102");var prepared=prepareKyc();
        kyc.apply(prepared,verified(prepared));
        assertEquals("BLOCKED",str(workflow(workflowId),"state"));
        assertEquals("EVIDENCE_INVALID",str(workflow(workflowId),"last_reason_code"));assertRisk(workflowId,10,0);
        assertEquals(0,count("mock_payment"));assertEquals(0,count("approval"));
        assertEquals(0,db.number(db.required("select count(*) n from agent_run where role='LOAN'"),"n"));
        var quarantine=db.required("select * from quarantine where run_id=?",prepared.input().runId());
        assertEquals("RUN",str(quarantine,"scope"));assertEquals("ACTIVE",str(quarantine,"status"));
        assertTrue(jobs.claim().isEmpty());
    }
    @ParameterizedTest @ValueSource(strings={"ID_DOC","FACE_MATCH"})
    void forgedFailureDoesNotProduceBusinessRejection(String kind) {
        crossIssue("customer-102",kind,"FAIL");UUID workflowId=start("customer-102");var prepared=prepareKyc();var i=prepared.input();
        kyc.apply(prepared,new KycContract.Response(i.requestId(),i.workflowId(),i.generation(),i.runId(),i.inputSnapshotHash(),
                new KycContract.Proposal(KycContract.ProposalStatus.NOT_VERIFIED,i.evidenceFacts().stream().map(KycContract.EvidenceFact::evidenceId).toList(),"Replay forged failure"),
                new KycContract.ModelMetadata("replay","KYC-PROMPT-1")));
        assertEquals("ON_HOLD",str(workflow(workflowId),"state"));assertEquals("EVIDENCE_MISSING",str(workflow(workflowId),"last_reason_code"));
        assertEquals(0,count("quarantine"));assertEquals(0,count("mock_payment"));
        assertEquals(0,db.number(db.required("select count(*) n from agent_run where role='LOAN'"),"n"));
    }
    @Test void persistedAndLiveRevalidationUseTheSameTypedAuthority() {
        UUID workflowId=ready102();UUID run=kycRun(workflowId);
        var result=db.required("select * from agent_result where run_id=?",run);
        crossIssue("customer-102","FACE_MATCH","PASS");
        var ids=db.query("select id from trusted_evidence where customer_id='customer-102'").stream().map(row->uuid(row,"id")).toList();
        assertEquals("EVIDENCE_INVALID",evidence.validateForCustomer("customer-102",ids,clock.now()).reasonCode());
        assertEquals("EVIDENCE_INVALID",evidence.revalidate(run,"customer-102",str(result,"evidence_bundle_hash"),clock.now()).reasonCode());
        assertEquals("EVIDENCE_INVALID",evidence.validateStored(uuid(result,"id"),clock.now()).reasonCode());
    }
    @Test void invalidRemediationReleaseAndLaterResumeDoNotMutateState() {
        UUID workflowId=start("customer-101");var prepared=prepareKyc();kyc.apply(prepared,verified(prepared));
        UUID incident=uuid(db.required("select * from quarantine where run_id=?",prepared.input().runId()),"id");
        var ids=issueEvidence101();crossIssue("customer-101","FACE_MATCH","PASS");
        var before=snapshot();
        var request=new ReleaseRequest(new ReleaseRequest.Remediation(DOCUMENT,1,ids,null,null,"Reviewed remediation"));
        assertThrows(ApiException.class,()->quarantines.release(SECURITY,incident,UUID.randomUUID(),request));
        assertEquals(before,snapshot());
        // Repair and release normally, then invalidate the issuer before the separate resume boundary.
        repairFace101();quarantines.release(SECURITY,incident,UUID.randomUUID(),request);
        crossIssue("customer-101","FACE_MATCH","PASS");before=snapshot();
        var error=assertThrows(ApiException.class,()->recovery.resume(REVIEWER,workflowId,UUID.randomUUID(),new ResumeRequest(1,"Resume reviewed remediation")));
        assertEquals("RECOVERY_CHECK_FAILED",error.reasonCode());assertEquals(before,snapshot());
    }
    private void repairFace101() {
        var row=db.required("select * from trusted_evidence where customer_id='customer-101' and evidence_type='FACE_MATCH'");
        var original=new LinkedHashMap<>(json.map(str(row,"original_json")));original.put("issuerId","mock-face-issuer");
        tx.executeWithoutResult(status->{db.gate();db.update("update trusted_evidence set issuer_id='mock-face-issuer',original_json=?,original_hash=? where id=?",json.write(original),json.hash(original),uuid(row,"id"));});
    }
    private Map<String,Object> snapshot() {
        var result=new LinkedHashMap<String,Object>();
        for(String table:List.of("workflow","workflow_job","workflow_stage","agent_run","agent_result","quarantine","approval","delegation_grant","risk_ledger","audit_event","action_request","mock_payment"))
            result.put(table,db.query("select row_to_json(t)::text body from "+table+" t order by row_to_json(t)::text"));
        return result;
    }
}
