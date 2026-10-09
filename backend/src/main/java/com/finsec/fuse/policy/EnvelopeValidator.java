package com.finsec.fuse.policy;

import java.time.Instant;
import java.security.MessageDigest;
import java.util.*;
import org.springframework.stereotype.Component;

/** Pure grant binding rules. Persisted snapshots come from Java repositories under the gate. */
@Component
public final class EnvelopeValidator {
    public void validate(GrantCodec.VerifiedGrant verified, StoredGrant stored, WorkflowBinding workflow,
                         RunBinding target, String authenticatedSourceRole, String expectedAction, Instant dbNow) {
        GrantClaims c = verified.claims();
        if (!c.equals(stored.claims()) || !Objects.equals(verified.kid(),stored.kid())
                || !MessageDigest.isEqual(verified.claimsBytes(),stored.claimsBytes())
                || !MessageDigest.isEqual(verified.actionBytes(),stored.actionBytes())
                || !MessageDigest.isEqual(verified.macBytes(),stored.macBytes())) fail("SIGNATURE_INVALID");
        if (!"ISSUED".equals(stored.status())) fail("SCOPE_EXCEEDED");
        if (!Objects.equals(c.sourceAgent(), authenticatedSourceRole)) fail("SCOPE_EXCEEDED");
        if (!Objects.equals(c.allowedAction(), expectedAction)) fail("SCOPE_EXCEEDED");
        requireEdge(c);
        if (!Objects.equals(c.workflowId(),workflow.workflowId())
                || !Objects.equals(c.rootAuthorizationId(),workflow.rootAuthorizationId())
                || !Objects.equals(c.principal(),workflow.principal())
                || !Objects.equals(c.originIntent(),workflow.originIntent())
                || !Objects.equals(c.customerId(),workflow.customerId())
                || c.amountKrw()!=workflow.amountKrw()
                || !Objects.equals(c.payoutAccountId(),workflow.payoutAccountId())
                || !Objects.equals(c.riskLedgerId(),workflow.riskLedgerId())) fail("CONTEXT_MISMATCH");
        if (c.generation()!=workflow.generation() || c.generation()!=target.generation()) fail("STALE_GENERATION");
        if (!Objects.equals(c.policyVersion(),workflow.policyVersion())) fail("CONTEXT_MISMATCH");
        if (!Objects.equals(c.targetRunId(),target.runId()) || !Objects.equals(c.workflowId(),target.workflowId())
                || !Objects.equals(c.targetAgent(),target.role()) || !Objects.equals(c.actionId(),target.actionId()))
            fail("CONTEXT_MISMATCH");
        if (!("QUEUED".equals(target.status()) || "RUNNING".equals(target.status()))) fail("CONTEXT_MISMATCH");
        if (dbNow.toEpochMilli() >= c.expiresAtEpochMs()) fail("GRANT_EXPIRED");
    }
    public static void requireEdge(GrantClaims c) {
        boolean root = c.depth()==1 && "FUSE".equals(c.sourceAgent()) && "KYC".equals(c.targetAgent())
                && "EVALUATE_KYC".equals(c.allowedAction()) && c.sourceRunId()==null && c.sourceResultId()==null
                && c.parentGrantId()==null && c.approvalId()==null;
        boolean loan = c.depth()==2 && "KYC".equals(c.sourceAgent()) && "LOAN".equals(c.targetAgent())
                && "CREATE_LOAN_RECOMMENDATION".equals(c.allowedAction()) && c.sourceRunId()!=null
                && c.sourceResultId()!=null && c.parentGrantId()!=null && c.approvalId()==null
                && c.evidenceBundleHash()!=null;
        boolean pay = c.depth()==3 && "LOAN".equals(c.sourceAgent()) && "PAYMENT".equals(c.targetAgent())
                && "EXECUTE_MOCK_PAYMENT".equals(c.allowedAction()) && c.sourceRunId()!=null
                && c.sourceResultId()!=null && c.parentGrantId()!=null && c.approvalId()!=null
                && c.evidenceBundleHash()!=null;
        if (!"FUSE".equals(c.issuer()) || !(root || loan || pay)) fail("SCOPE_EXCEEDED");
    }
    private static void fail(String reason) { throw new PolicyException(reason); }
    public record WorkflowBinding(UUID workflowId,int generation,UUID rootAuthorizationId,String principal,
            String originIntent,String customerId,long amountKrw,UUID payoutAccountId,String policyVersion,UUID riskLedgerId) {}
    public record RunBinding(UUID runId,UUID workflowId,int generation,String role,String status,UUID actionId) {}
    public record StoredGrant(GrantClaims claims,String kid,String status,byte[] claimsBytes,byte[] actionBytes,byte[] macBytes) {
        public StoredGrant { claimsBytes=claimsBytes.clone(); actionBytes=actionBytes.clone(); macBytes=macBytes.clone(); }
        @Override public byte[] claimsBytes(){return claimsBytes.clone();}
        @Override public byte[] actionBytes(){return actionBytes.clone();}
        @Override public byte[] macBytes(){return macBytes.clone();}
    }
}
