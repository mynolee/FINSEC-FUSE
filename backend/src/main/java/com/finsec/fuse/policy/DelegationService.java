package com.finsec.fuse.policy;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.observation.SecurityCheckObservation;
import com.finsec.fuse.persistence.Db;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Service;
import static com.finsec.fuse.policy.PolicyRows.*;

/** Central issuer and registry validator. All calls that authorize work must be inside gate→workflow locks. */
@Service
public class DelegationService {
    private final Db db;
    private final Json json;
    private final FusePolicy policy;
    private final GrantCodec codec;
    private final EnvelopeValidator validator;
    private final EvidenceValidator evidence;
    private final QuarantineMatcher quarantine;
    public DelegationService(Db db,Json json,FusePolicy policy,GrantCodec codec,EnvelopeValidator validator,
                             EvidenceValidator evidence,QuarantineMatcher quarantine) {
        this.db=db;this.json=json;this.policy=policy;this.codec=codec;this.validator=validator;
        this.evidence=evidence;this.quarantine=quarantine;
    }

    public GrantTransport issue(UUID workflowId,String targetRole,UUID sourceRunId,UUID targetRunId,
                                UUID sourceResultId,UUID parentGrantId,UUID actionId,UUID approvalId,
                                String evidenceBundleHash,byte[] actionBytes,Instant dbNow) {
        var w=workflow(workflowId);
        String source; String action; int depth;
        switch(targetRole) {
            case "KYC" -> {source="FUSE";action="EVALUATE_KYC";depth=1;}
            case "LOAN" -> {source="KYC";action="CREATE_LOAN_RECOMMENDATION";depth=2;}
            case "PAYMENT" -> {source="LOAN";action="EXECUTE_MOCK_PAYMENT";depth=3;}
            default -> throw new PolicyException("SCOPE_EXCEEDED");
        }
        GrantClaims c=new GrantClaims(UUID.randomUUID(),workflowId,integer(w,"generation"),uuid(w,"root_authorization_id"),
                str(w,"principal_id"),str(w,"origin_intent"),"FUSE",source,targetRole,sourceRunId,targetRunId,action,
                str(w,"customer_id"),number(w,"amount_krw"),uuid(w,"payout_account_id"),sourceResultId,
                evidenceBundleHash,parentGrantId,depth,actionId,Json.sha256(actionBytes),str(w,"policy_version"),
                uuid(w,"risk_ledger_id"),approvalId,grantExpiresAt(w,targetRole,approvalId,dbNow).toEpochMilli());
        EnvelopeValidator.requireEdge(c);
        GrantTransport transport=codec.sign(c,actionBytes);
        var signed=codec.verify(transport);
        requireApplicationBinding(signed,w);
        // Never replace an expired grant under the same action. Unique action/target constraints enforce this too.
        if(db.one("SELECT id FROM delegation_grant WHERE action_id=? OR target_run_id=?",actionId,targetRunId).isPresent())
            throw new PolicyException("SCOPE_EXCEEDED");
        var target=run(targetRunId);
        validator.validate(signed,new EnvelopeValidator.StoredGrant(c,signed.kid(),"ISSUED",signed.claimsBytes(),
                signed.actionBytes(),signed.macBytes()),binding(w),runBinding(target),source,action,dbNow);
        checkPrerequisites(c,w,target,dbNow);
        db.update("""
            INSERT INTO delegation_grant(id,workflow_id,generation,root_authorization_id,principal_id,origin_intent,
              issuer,source_agent,target_agent,source_run_id,target_run_id,allowed_action,customer_id,amount_krw,
              payout_account_id,source_result_id,evidence_bundle_hash,parent_grant_id,depth,action_id,payload_hash,
              policy_version,risk_ledger_id,approval_id,format,kid,claims_bytes,action_bytes,mac_bytes,expires_at,status)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'ISSUED')
            """,c.grantId(),c.workflowId(),c.generation(),c.rootAuthorizationId(),c.principal(),c.originIntent(),c.issuer(),
                c.sourceAgent(),c.targetAgent(),c.sourceRunId(),c.targetRunId(),c.allowedAction(),c.customerId(),c.amountKrw(),
                c.payoutAccountId(),c.sourceResultId(),c.evidenceBundleHash(),c.parentGrantId(),c.depth(),c.actionId(),c.payloadHash(),
                c.policyVersion(),c.riskLedgerId(),c.approvalId(),GrantCodec.FORMAT,signed.kid(),signed.claimsBytes(),
                signed.actionBytes(),signed.macBytes(),Instant.ofEpochMilli(c.expiresAtEpochMs()));
        return transport;
    }

    public GrantClaims validate(GrantTransport transport,String authenticatedSourceRole,UUID workflowId,
                                UUID targetRunId,String expectedAction,Instant dbNow) {
        // Authentication, strict parsing and body integrity are common to both experiment arms.
        var verified=verifyBasicTransport(transport);
        try (var ignored=SecurityCheckObservation.enter(SecurityCheckObservation.Check.DELEGATION_VALIDATION)) {
            codec.requireActionBindings(verified);
            return validateGrant(verified,authenticatedSourceRole,workflowId,targetRunId,expectedAction,dbNow);
        }
    }
    /** Only the isolated experiment subclass omits the additional FUSE policy checks. */
    protected final GrantCodec.VerifiedGrant verifyBasicTransport(GrantTransport transport) {
        return codec.verifyBasic(transport);
    }
    private GrantClaims validateGrant(GrantCodec.VerifiedGrant verified,String authenticatedSourceRole,UUID workflowId,
                                      UUID targetRunId,String expectedAction,Instant dbNow) {
        var c=verified.claims();
        if(!workflowId.equals(c.workflowId()) || !targetRunId.equals(c.targetRunId())) throw new PolicyException("CONTEXT_MISMATCH");
        var w=workflow(workflowId);
        requireApplicationBinding(verified,w);
        var stored=grant(c.grantId());
        var target=run(targetRunId);
        validator.validate(verified,stored(stored),binding(w),runBinding(target),authenticatedSourceRole,expectedAction,dbNow);
        checkPrerequisites(c,w,target,dbNow);
        return c;
    }

    /** Optional action aliases cannot override the application selected by the trusted workflow. */
    private void requireApplicationBinding(GrantCodec.VerifiedGrant verified,Map<String,Object> workflow) {
        // Callers reach this only after strict transport authentication and action JSON validation.
        var action=json.map(new String(verified.actionBytes(),java.nio.charset.StandardCharsets.UTF_8));
        String applicationId=uuid(workflow,"application_id").toString();
        for(String field:List.of("loanApplicationId","applicationId")) {
            if(action.containsKey(field) && !applicationId.equals(action.get(field)))
                throw new PolicyException("CONTEXT_MISMATCH");
        }
    }

    public GrantTransport transport(UUID grantId) {
        var row=grant(grantId);var encoder=Base64.getUrlEncoder().withoutPadding();
        return new GrantTransport(new GrantTransport.Grant(str(row,"format"),str(row,"kid"),
                encoder.encodeToString((byte[])row.get("claims_bytes")),encoder.encodeToString((byte[])row.get("mac_bytes"))),
                encoder.encodeToString((byte[])row.get("action_bytes")));
    }

    /** KYC/Loan at actual start, PAYMENT only in the atomic mock-payment commit. */
    public void consume(UUID grantId,Instant dbNow) {
        if(db.update("UPDATE delegation_grant SET status='CONSUMED',consumed_at=? WHERE id=? AND status='ISSUED' AND expires_at>?",
                dbNow,grantId,dbNow)!=1) throw new PolicyException("GRANT_EXPIRED");
    }

    private void checkPrerequisites(GrantClaims c,Map<String,Object> w,Map<String,Object> target,Instant now) {
        if(!policy.allowedEdges().getOrDefault(c.sourceAgent(),List.of()).contains(c.targetAgent()))
            throw new PolicyException("SCOPE_EXCEEDED");
        if(!policy.policyVersion().equals(c.policyVersion()) || c.amountKrw()>policy.maxAmountKrw())
            throw new PolicyException("CONTEXT_MISMATCH");
        if(!Objects.equals(str(target,"agent_id"),c.targetAgent())) throw new PolicyException("SCOPE_EXCEEDED");
        requireAgent(str(target,"agent_id"),integer(target,"agent_version"),c.targetAgent());
        if(quarantine.isQuarantined(c.targetRunId()) || quarantine.workflowQuarantined(c.workflowId()))
            throw new PolicyException("QUARANTINED");
        if(c.depth()==1) requireAgent("FUSE",1,"FUSE_WORKER");
        else {
            checkLineage(c,w);
            UUID kycResult=uuid(w,"current_kyc_result_id");
            if(kycResult==null) throw new PolicyException("EVIDENCE_MISSING");
            EvidenceDecision e=evidence.validateStored(kycResult,now);
            if(!e.validated() || !Objects.equals(e.evidenceBundleHash(),c.evidenceBundleHash()))
                throw new PolicyException(e.validated()?"EVIDENCE_INVALID":e.reasonCode());
        }
        boolean approved=false;
        if(c.depth()==3) { checkApproval(c,w,now); approved=true; }
        var stage=db.one("SELECT * FROM workflow_stage WHERE workflow_id=? AND stage=?",c.workflowId(),c.targetAgent())
                .orElseThrow(()->new PolicyException("CONTEXT_MISMATCH"));
        int extra=c.depth()==3 ? (integer(w,"reserved_risk")>0?0:policy.paymentRisk())
                : integer(stage,"used_points")>0?0:c.depth()==1?policy.kycRisk():policy.loanRisk();
        long limit=policy.automaticRiskLimit()+(approved?policy.approvalExtraRisk():0);
        if((long)integer(w,"used_risk")+integer(w,"reserved_risk")+extra>limit)
            throw new PolicyException("RISK_LIMIT_EXCEEDED");
    }

    private void checkLineage(GrantClaims child,Map<String,Object> w) {
        GrantClaims cursor=child;
        Set<UUID> seen=new HashSet<>();
        while(cursor.depth()>1) {
            if(cursor.parentGrantId()==null || !seen.add(cursor.parentGrantId())) throw new PolicyException("SCOPE_EXCEEDED");
            var parentRow=grant(cursor.parentGrantId());
            var verified=codec.verify(transport(cursor.parentGrantId()));
            GrantClaims parent=verified.claims();
            var registered=stored(parentRow);
            if(!parent.equals(registered.claims()) || !Objects.equals(verified.kid(),registered.kid())
                    || !MessageDigest.isEqual(verified.claimsBytes(),registered.claimsBytes())
                    || !MessageDigest.isEqual(verified.actionBytes(),registered.actionBytes())
                    || !MessageDigest.isEqual(verified.macBytes(),registered.macBytes())) throw new PolicyException("SIGNATURE_INVALID");
            EnvelopeValidator.requireEdge(parent);
            if(!"CONSUMED".equals(registered.status()) || parent.depth()!=cursor.depth()-1
                    || !Objects.equals(parent.targetRunId(),cursor.sourceRunId())
                    || !Objects.equals(parent.targetAgent(),cursor.sourceAgent())
                    || !sameWorkflow(parent,child)
                    || (parent.depth()>1 && !Objects.equals(parent.evidenceBundleHash(),child.evidenceBundleHash())))
                throw new PolicyException("CONTEXT_MISMATCH");
            var source=run(cursor.sourceRunId());
            var result=db.one("SELECT * FROM agent_result WHERE id=?",cursor.sourceResultId())
                    .orElseThrow(()->new PolicyException("CONTEXT_MISMATCH"));
            if(!"VALIDATED".equals(str(source,"status")) || !"VALIDATED".equals(str(result,"status"))
                    || !Objects.equals(uuid(source,"workflow_id"),child.workflowId())
                    || integer(source,"generation")!=child.generation()
                    || !Objects.equals(uuid(result,"run_id"),uuid(source,"id"))
                    || !Objects.equals(uuid(result,"workflow_id"),child.workflowId())
                    || integer(result,"generation")!=child.generation()
                    || !Objects.equals(str(source,"role"),cursor.sourceAgent())
                    || !Objects.equals(uuid(source,"action_id"),parent.actionId())) throw new PolicyException("CONTEXT_MISMATCH");
            if(!Objects.equals(str(source,"agent_id"),cursor.sourceAgent())) throw new PolicyException("SCOPE_EXCEEDED");
            requireAgent(str(source,"agent_id"),integer(source,"agent_version"),cursor.sourceAgent());
            if(quarantine.isQuarantined(uuid(source,"id"))) throw new PolicyException("QUARANTINED");
            // Build the path from persisted dependencies. A QUEUED current target has no edge yet.
            var dependency=db.one("SELECT * FROM run_dependency WHERE child_run_id=?",parent.targetRunId());
            if(parent.depth()==1) {
                if(dependency.isPresent()) throw new PolicyException("SCOPE_EXCEEDED");
            } else {
                if(dependency.isEmpty() || !Objects.equals(uuid(dependency.get(),"parent_run_id"),parent.sourceRunId())
                        || !Objects.equals(uuid(dependency.get(),"parent_result_id"),parent.sourceResultId())
                        || !Objects.equals(uuid(dependency.get(),"workflow_id"),child.workflowId())
                        || integer(dependency.get(),"generation")!=child.generation()) throw new PolicyException("CONTEXT_MISMATCH");
            }
            // A consumed ancestor is historical proof. Its old 60-second start expiry is deliberately not checked.
            cursor=parent;
        }
        UUID expected=child.depth()==2?uuid(w,"current_kyc_result_id"):uuid(w,"current_loan_result_id");
        if(!Objects.equals(child.sourceResultId(),expected)) throw new PolicyException("CONTEXT_MISMATCH");
        var targetEdge=db.one("SELECT * FROM run_dependency WHERE child_run_id=?",child.targetRunId());
        if(targetEdge.isPresent() && (!Objects.equals(uuid(targetEdge.get(),"parent_run_id"),child.sourceRunId())
                || !Objects.equals(uuid(targetEdge.get(),"parent_result_id"),child.sourceResultId())))
            throw new PolicyException("CONTEXT_MISMATCH");
        if("RUNNING".equals(str(run(child.targetRunId()),"status")) && targetEdge.isEmpty())
            throw new PolicyException("CONTEXT_MISMATCH");
    }

    private Instant grantExpiresAt(Map<String,Object> workflow,String targetRole,UUID approvalId,Instant now) {
        if(!"PAYMENT".equals(targetRole)) return now.plusSeconds(policy.grantTtlSeconds());
        // Read authority from the trusted approval row under the caller's gate/workflow locks.
        // Request-body TTL values never choose or extend a payment grant's start window.
        var approval=db.one("SELECT expires_at FROM approval WHERE id=? AND workflow_id=? AND generation=?",
                approvalId,uuid(workflow,"id"),integer(workflow,"generation"))
                .orElseThrow(()->new PolicyException("APPROVAL_INVALID"));
        Instant approvalExpiry=instant(approval,"expires_at");
        if(!now.isBefore(approvalExpiry)) throw new PolicyException("APPROVAL_REQUIRED");
        Instant startDeadline=now.plusSeconds(60);
        return approvalExpiry.isBefore(startDeadline)?approvalExpiry:startDeadline;
    }

    private void checkApproval(GrantClaims c,Map<String,Object> w,Instant now) {
        var a=db.one("SELECT * FROM approval WHERE id=?",c.approvalId()).orElseThrow(()->new PolicyException("APPROVAL_INVALID"));
        if(!List.of("AVAILABLE","RESERVED").contains(str(a,"status"))) throw new PolicyException("APPROVAL_INVALID");
        if(!now.isBefore(instant(a,"expires_at"))) throw new PolicyException("APPROVAL_REQUIRED");
        if(!Objects.equals(uuid(a,"workflow_id"),c.workflowId()) || integer(a,"generation")!=c.generation()
                || !Objects.equals(str(a,"customer_id"),c.customerId()) || number(a,"amount_krw")!=c.amountKrw()
                || !Objects.equals(uuid(a,"payout_account_id"),c.payoutAccountId())
                || !Objects.equals(uuid(a,"kyc_result_id"),uuid(w,"current_kyc_result_id"))
                || !Objects.equals(uuid(a,"loan_result_id"),c.sourceResultId())
                || !Objects.equals(str(a,"evidence_bundle_hash"),c.evidenceBundleHash())
                || !Objects.equals(str(a,"policy_version"),c.policyVersion())
                || integer(a,"extra_risk")!=policy.approvalExtraRisk()
                || integer(a,"risk_limit")!=policy.automaticRiskLimit()+policy.approvalExtraRisk()
                || ("RESERVED".equals(str(a,"status")) && !Objects.equals(uuid(a,"reserved_action_id"),c.actionId())))
            throw new PolicyException("APPROVAL_INVALID");
        var loan=db.one("SELECT result_hash FROM agent_result WHERE id=? AND status='VALIDATED'",c.sourceResultId())
                .orElseThrow(()->new PolicyException("APPROVAL_INVALID"));
        if(!Objects.equals(str(a,"loan_result_hash"),str(loan,"result_hash"))) throw new PolicyException("APPROVAL_INVALID");
    }
    private void requireAgent(String agent,int version,String role) {
        if(db.one("SELECT agent_id FROM agent_registry WHERE agent_id=? AND version=? AND role=? AND status='ACTIVE'",agent,version,role).isEmpty())
            throw new PolicyException("SCOPE_EXCEEDED");
    }
    private static boolean sameWorkflow(GrantClaims a,GrantClaims b) {
        return Objects.equals(a.workflowId(),b.workflowId()) && a.generation()==b.generation()
                && Objects.equals(a.rootAuthorizationId(),b.rootAuthorizationId()) && Objects.equals(a.principal(),b.principal())
                && Objects.equals(a.originIntent(),b.originIntent()) && Objects.equals(a.customerId(),b.customerId())
                && a.amountKrw()==b.amountKrw() && Objects.equals(a.payoutAccountId(),b.payoutAccountId())
                && Objects.equals(a.policyVersion(),b.policyVersion()) && Objects.equals(a.riskLedgerId(),b.riskLedgerId());
    }
    private Map<String,Object> workflow(UUID id) { return db.one("SELECT w.*,a.customer_id,a.amount_krw,a.payout_account_id FROM workflow w JOIN loan_application a ON a.id=w.application_id WHERE w.id=?",id).orElseThrow(()->new PolicyException("CONTEXT_MISMATCH")); }
    private Map<String,Object> run(UUID id) { return db.one("SELECT * FROM agent_run WHERE id=?",id).orElseThrow(()->new PolicyException("CONTEXT_MISMATCH")); }
    private Map<String,Object> grant(UUID id) { return db.one("SELECT * FROM delegation_grant WHERE id=?",id).orElseThrow(()->new PolicyException("SIGNATURE_INVALID")); }
    private static EnvelopeValidator.WorkflowBinding binding(Map<String,Object> w) {
        return new EnvelopeValidator.WorkflowBinding(uuid(w,"id"),integer(w,"generation"),uuid(w,"root_authorization_id"),
                str(w,"principal_id"),str(w,"origin_intent"),str(w,"customer_id"),number(w,"amount_krw"),uuid(w,"payout_account_id"),str(w,"policy_version"),uuid(w,"risk_ledger_id"));
    }
    private static EnvelopeValidator.RunBinding runBinding(Map<String,Object> r) {
        return new EnvelopeValidator.RunBinding(uuid(r,"id"),uuid(r,"workflow_id"),integer(r,"generation"),str(r,"role"),str(r,"status"),uuid(r,"action_id"));
    }
    private static EnvelopeValidator.StoredGrant stored(Map<String,Object> r) {
        if(!GrantCodec.FORMAT.equals(str(r,"format"))) throw new PolicyException("SIGNATURE_INVALID");
        var c=new GrantClaims(uuid(r,"id"),uuid(r,"workflow_id"),integer(r,"generation"),uuid(r,"root_authorization_id"),str(r,"principal_id"),
                str(r,"origin_intent"),str(r,"issuer"),str(r,"source_agent"),str(r,"target_agent"),uuid(r,"source_run_id"),uuid(r,"target_run_id"),
                str(r,"allowed_action"),str(r,"customer_id"),number(r,"amount_krw"),uuid(r,"payout_account_id"),uuid(r,"source_result_id"),
                str(r,"evidence_bundle_hash"),uuid(r,"parent_grant_id"),integer(r,"depth"),uuid(r,"action_id"),str(r,"payload_hash"),str(r,"policy_version"),
                uuid(r,"risk_ledger_id"),uuid(r,"approval_id"),instant(r,"expires_at").toEpochMilli());
        return new EnvelopeValidator.StoredGrant(c,str(r,"kid"),str(r,"status"),(byte[])r.get("claims_bytes"),(byte[])r.get("action_bytes"),(byte[])r.get("mac_bytes"));
    }
}
