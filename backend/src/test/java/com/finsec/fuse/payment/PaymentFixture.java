package com.finsec.fuse.payment;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.quarantine.*;
import com.finsec.fuse.testing.FuseIntegrationTest;
import com.finsec.fuse.workflow.*;
import java.util.*;
import org.junit.jupiter.api.AfterEach;
import org.springframework.beans.factory.annotation.Autowired;

public abstract class PaymentFixture extends FuseIntegrationTest {
    @Autowired protected WorkflowService workflows;
    @Autowired protected JobTransactions jobs;
    @Autowired protected KycTransactions kyc;
    @Autowired protected LoanTransactions loans;
    @Autowired protected ApprovalService approvals;
    @Autowired protected PaymentTxService payments;
    @Autowired protected PaymentAgentService paymentAgent;
    @Autowired protected PaymentTestHooks hooks;
    @Autowired protected QuarantineService quarantines;
    @Autowired protected RecoveryService recovery;
    protected static final Actor REVIEWER=new Actor("staff-01","LOAN_REVIEWER",Set.of("customer-101","customer-102","customer-103","customer-104"));
    protected static final Actor SECURITY=new Actor("security-01","SECURITY_OPERATOR",Set.of("customer-101","customer-102","customer-103","customer-104"));
    protected static final UUID DOCUMENT=UUID.fromString("00000000-0000-4000-8000-000000000201");
    @AfterEach void resetHooks(){hooks.reset();}
    protected UUID start(String customer) {
        String suffix=customer.substring(customer.length()-3);
        var result=workflows.start(new Actor(customer,"CUSTOMER",Set.of(customer)),UUID.randomUUID(),
            new StartWorkflowRequest("APP-DEMO-"+suffix+"-001",customer,1000000L,UUID.fromString("00000000-0000-4000-8000-000000000"+suffix)));
        return (UUID)result.get("workflowId");
    }
    protected KycContract.Prepared prepareKyc() {
        var lease=jobs.claim().orElseThrow();assertEquals("KYC",lease.phase());
        return kyc.prepare(lease.jobId(),lease.token()).orElseThrow();
    }
    protected KycContract.Response verified(KycContract.Prepared prepared) {
        var i=prepared.input();return new KycContract.Response(i.requestId(),i.workflowId(),i.generation(),i.runId(),i.inputSnapshotHash(),
            new KycContract.Proposal(KycContract.ProposalStatus.VERIFIED,i.evidenceFacts().stream().map(KycContract.EvidenceFact::evidenceId).toList(),"Replay fixture proposal"),
            new KycContract.ModelMetadata("replay","KYC-PROMPT-1"));
    }
    protected UUID ready102() {
        UUID id=start("customer-102");var p=prepareKyc();kyc.apply(p,verified(p));
        var loan=jobs.claim().orElseThrow();assertEquals("LOAN",loan.phase());loans.execute(loan.jobId(),loan.token());
        assertEquals("WAIT_APPROVAL",str(workflow(id),"state"));return id;
    }
    protected JobTransactions.Lease approve(UUID workflowId) {
        var preview=approvals.preview(REVIEWER,workflowId);
        approvals.decide(REVIEWER,workflowId,UUID.randomUUID(),new ApprovalRequest(ApprovalRequest.Decision.APPROVE,(String)preview.get("reviewSnapshotHash"),"Fixture reviewed"));
        var pay=jobs.claim().orElseThrow();assertEquals("PAY",pay.phase());return pay;
    }
    protected Map<String,Object> workflow(UUID id){return db.required("select * from workflow where id=?",id);}
    protected long count(String table){return ((Number)db.required("select count(*) as n from "+table).get("n")).longValue();}
    protected long events(String event){return ((Number)db.required("select count(*) as n from risk_ledger where event_type=?",event).get("n")).longValue();}
    protected UUID kycRun(UUID workflowId){return uuid(db.required("select id from agent_run where workflow_id=? and role='KYC' order by run_index desc limit 1",workflowId),"id");}
    protected void assertRisk(UUID id,int used,int reserved){assertEquals(used,integer(workflow(id),"used_risk"));assertEquals(reserved,integer(workflow(id),"reserved_risk"));}
    protected List<UUID> issueEvidence101() {
        var ids=new ArrayList<UUID>();
        tx.executeWithoutResult(status->{db.gate();for(int index=1;index<=2;index++) {
            UUID id=UUID.fromString("00000000-0000-4000-8000-00000000101"+index);ids.add(id);
            String type=index==1?"ID_DOC":"FACE_MATCH",issuer=index==1?"mock-id-issuer":"mock-face-issuer";
            var now=clock.now();var issued=now.minusSeconds(60);var expires=now.plusSeconds(1800);
            var original=Json.ordered("customerId","customer-101","evidenceType",type,"issuerId",issuer,"outcome","PASS","issuedAt",issued.toString(),"expiresAt",expires.toString());
            db.update("insert into trusted_evidence(id,customer_id,evidence_type,issuer_id,version,outcome,original_json,original_hash,status,issued_at,expires_at) values(?,'customer-101',?,?,1,'PASS',?,?,'ACTIVE',?,?)",id,type,issuer,json.write(original),json.hash(original),issued,expires);
        }});return ids;
    }
}
