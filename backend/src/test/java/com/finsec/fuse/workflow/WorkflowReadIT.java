package com.finsec.fuse.workflow;

import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.testing.FuseIntegrationTest;
import com.finsec.fuse.payment.ApprovalRequest;
import com.finsec.fuse.payment.ApprovalService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class WorkflowReadIT extends FuseIntegrationTest {
    @Autowired WorkflowService workflows;
    @Autowired WorkflowQueryService queries;
    @Autowired JobTransactions jobs;
    @Autowired KycTransactions kyc;
    @Autowired LoanTransactions loans;
    @Autowired ApprovalService approvals;
    private Actor customer(int id){return new Actor("customer-"+id,"CUSTOMER",Set.of("customer-"+id));}
    private final Actor reviewer=new Actor("staff-01","LOAN_REVIEWER",Set.of("customer-101","customer-102"));
    private UUID start(int id) {
        var response=workflows.start(customer(id),UUID.randomUUID(),new StartWorkflowRequest("APP-DEMO-"+id+"-001","customer-"+id,1_000_000L,UUID.fromString("00000000-0000-4000-8000-000000000"+id)));
        return (UUID)response.get("workflowId");
    }
    @Test void listAndDetailRespectTheSameAuthenticatedCustomerScope() {
        UUID first=start(101),second=start(102);
        var customerList=queries.list(customer(101),null,0,20);
        assertEquals(1L,customerList.get("total"));assertEquals(2L,queries.list(reviewer,null,0,20).get("total"));
        assertEquals(403,assertThrows(ApiException.class,()->queries.detail(customer(101),second)).status());
        var visible=queries.detail(customer(101),first);
        assertTrue(visible.get("payoutAccountId").toString().startsWith("••••"));assertEquals(false,visible.get("canApprove"));
        assertEquals(UUID.fromString("00000000-0000-4000-8000-000000000101"),queries.detail(reviewer,first).get("payoutAccountId"));
        assertEquals(400,assertThrows(ApiException.class,()->queries.list(reviewer,null,-1,20)).status());
        assertEquals(400,assertThrows(ApiException.class,()->queries.list(reviewer,"MADE_UP",0,20)).status());
    }
    @Test void staffTraceContainsActualReadsButNeverAuthenticationMaterial() {
        UUID workflowId=start(102);var lease=jobs.claim().orElseThrow();kyc.prepare(lease.jobId(),lease.token()).orElseThrow();
        assertEquals(403,assertThrows(ApiException.class,()->queries.trace(customer(102),workflowId)).status());
        var trace=queries.trace(reviewer,workflowId);String rendered=json.write(trace);
        assertEquals(1,((List<?>)trace.get("runs")).size());assertEquals(1,((List<?>)trace.get("sourceUses")).size());
        assertEquals(2,((List<?>)trace.get("evidenceUses")).size());assertEquals(1,((List<?>)trace.get("grants")).size());
        assertFalse(rendered.contains("macBytes"));assertFalse(rendered.contains("claimsBytes"));assertFalse(rendered.contains("leaseToken"));
        assertFalse(rendered.contains("payloadBase64Url"));assertFalse(rendered.contains("inputBytes"));
        var active=(Map<?,?>)queries.detail(reviewer,workflowId).get("activeJob");
        assertEquals(Set.of("jobId","phase","state"),active.keySet());
    }
    @Test void approvedHistoryProjectsPersistedAmountWithScopedSafeTrace() {
        assertApprovalHistoryProjectsPersistedAmount(ApprovalRequest.Decision.APPROVE);
    }
    @Test void rejectedHistoryProjectsPersistedAmountWithScopedSafeTrace() {
        assertApprovalHistoryProjectsPersistedAmount(ApprovalRequest.Decision.REJECT);
    }
    private void assertApprovalHistoryProjectsPersistedAmount(ApprovalRequest.Decision decision) {
        UUID workflowId=start(102);
        var lease=jobs.claim().orElseThrow();
        var prepared=kyc.prepare(lease.jobId(),lease.token()).orElseThrow();
        var input=prepared.input();
        kyc.apply(prepared,new KycContract.Response(input.requestId(),input.workflowId(),input.generation(),input.runId(),input.inputSnapshotHash(),
            new KycContract.Proposal(KycContract.ProposalStatus.VERIFIED,input.evidenceFacts().stream().map(KycContract.EvidenceFact::evidenceId).toList(),"History fixture"),
            new KycContract.ModelMetadata("replay","KYC-PROMPT-1")));
        var loan=jobs.claim().orElseThrow();assertEquals("LOAN",loan.phase());loans.execute(loan.jobId(),loan.token());
        var preview=approvals.preview(reviewer,workflowId);
        var response=approvals.decide(reviewer,workflowId,UUID.randomUUID(),
            new ApprovalRequest(decision,(String)preview.get("reviewSnapshotHash"),"History fixture reviewed"));
        UUID approvalId=(UUID)response.get("approvalId");
        var stored=db.required("SELECT id,generation,status,amount_krw FROM approval WHERE id=?",approvalId);
        assertEquals(1_000_000L,((Number)stored.get("amount_krw")).longValue());
        assertEquals(decision==ApprovalRequest.Decision.APPROVE?"AVAILABLE":"REJECTED",stored.get("status"));
        var security=new Actor("security-history","SECURITY_OPERATOR",Set.of("customer-102"));
        for(Actor authorized:List.of(reviewer,security)) {
            var trace=queries.trace(authorized,workflowId);
            var history=(List<?>)trace.get("approvals");assertEquals(1,history.size());
            var row=(Map<?,?>)history.getFirst();
            assertEquals(approvalId,row.get("approvalId"));assertEquals(stored.get("generation"),row.get("generation"));
            assertEquals(stored.get("status"),row.get("status"));
            assertEquals(((Number)stored.get("amount_krw")).longValue(),((Number)row.get("amountKrw")).longValue());
            assertEquals(Set.of("approvalId","generation","actorId","status","amountKrw","reviewSnapshotHash","extraRisk","riskLimit","expiresAt","createdAt"),row.keySet());
            String rendered=json.write(trace);
            for(String secret:List.of("macBytes","claimsBytes","leaseToken","payloadBase64Url","inputBytes"))assertFalse(rendered.contains(secret));
        }
        for(Actor denied:List.of(customer(102),customer(101),
            new Actor("foreign-reviewer","LOAN_REVIEWER",Set.of("customer-101")),
            new Actor("foreign-security","SECURITY_OPERATOR",Set.of("customer-101"))))
            assertEquals(403,assertThrows(ApiException.class,()->queries.trace(denied,workflowId)).status());
        assertEquals(0L,((Number)db.required("SELECT count(*) AS n FROM mock_payment WHERE workflow_id=?",workflowId).get("n")).longValue());
    }

}
