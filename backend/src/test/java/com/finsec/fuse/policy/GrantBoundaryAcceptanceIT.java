package com.finsec.fuse.policy;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;

import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.payment.PaymentFixture;
import com.finsec.fuse.workflow.StartWorkflowRequest;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;

/** Synthetic admission-boundary regressions. No external contract assets or model prompts are embedded. */
class GrantBoundaryAcceptanceIT extends PaymentFixture {
    private static final String LOAN_ACTION="CREATE_LOAN_RECOMMENDATION";
    @Autowired DelegationService grants;
    @Autowired GrantCodec codec;

    @Test void externalForgedFreshLoanGrantIsRejectedBeforeAttributionWithoutAnyStateChange() {
        var fresh=freshLoan();
        var before=snapshot();
        var legitimate=fresh.transport();
        byte[] tag=Base64.getUrlDecoder().decode(legitimate.grant().macBase64Url());
        tag[0]^=1;
        var forged=new GrantTransport(new GrantTransport.Grant(legitimate.grant().format(),legitimate.grant().kid(),
                legitimate.grant().payloadBase64Url(),Base64.getUrlEncoder().withoutPadding().encodeToString(tag)),
                legitimate.actionPayloadBase64Url());
        assertDenied("SIGNATURE_INVALID",fresh,forged,clock.now());
        // Even impossible context IDs cannot be looked up or attributed before authentication.
        assertEquals("SIGNATURE_INVALID",assertThrows(PolicyException.class,()->
                grants.validate(forged,"KYC",UUID.randomUUID(),UUID.randomUUID(),LOAN_ACTION,clock.now())).reasonCode());
        assertEquals(before,snapshot());
        assertEquals("KYC_VALIDATED",str(workflow(fresh.workflowId()),"state"));
        assertRisk(fresh.workflowId(),10,0);
        assertEquals(fresh.claims(),validate(fresh,legitimate,clock.now()));
    }

    @Test void unusedLoanGrantExpiresAtExactDeadlineAndCannotBeRefreshedForTheSameAction() {
        var fresh=freshLoan();
        Instant deadline=Instant.ofEpochMilli(fresh.claims().expiresAtEpochMs());
        assertEquals(fresh.claims(),validate(fresh,fresh.transport(),deadline.minusMillis(1)));
        var before=snapshot();
        assertDenied("GRANT_EXPIRED",fresh,fresh.transport(),deadline);
        assertEquals("SCOPE_EXCEEDED",assertThrows(PolicyException.class,()->tx.execute(status->{
            db.gate();db.lockWorkflow(fresh.workflowId());
            return issue(fresh,fresh.claims().parentGrantId(),deadline);
        })).reasonCode());
        assertEquals(before,snapshot());
        assertEquals("ISSUED",str(db.required("select * from delegation_grant where id=?",fresh.claims().grantId()),"status"));
        assertRisk(fresh.workflowId(),10,0);
        assertEquals(0,count("mock_payment"));
    }

    @ParameterizedTest
    @ValueSource(strings={"workflowId","customerId","amountKrw","payoutAccountId","originIntent","riskLedgerId"})
    void authenticatedProposalCannotChangeTheGrantBoundContext(String field) {
        var fresh=freshLoan();
        var body=new LinkedHashMap<String,Object>(json.map(new String(fresh.actionBytes(),java.nio.charset.StandardCharsets.UTF_8)));
        body.put(field,switch(field) {
            case "amountKrw" -> fresh.claims().amountKrw()+1;
            case "customerId" -> "customer-103";
            case "originIntent" -> "UNRELATED_SYNTHETIC_INTENT";
            default -> UUID.randomUUID().toString();
        });
        byte[] changedBody=json.bytes(body);
        var fields=fresh.claims().canonical(json);fields.put("payloadHash",Json.sha256(changedBody));
        var signed=codec.sign(json.read(json.write(fields),GrantClaims.class),changedBody);
        // The HMAC and body hash are genuinely valid; this must reach semantic binding checks.
        assertEquals(Json.sha256(changedBody),codec.verifyBasic(signed).claims().payloadHash());
        var before=snapshot();
        assertDenied("CONTEXT_MISMATCH",fresh,signed,clock.now());
        assertEquals(before,snapshot());
        assertRisk(fresh.workflowId(),10,0);
    }

    @Test void unrelatedConsumedParentCannotAuthorizeAFreshLoanGrant() {
        UUID other=startCustomerFromRegistry("customer-103");
        var prepared=prepareKyc();kyc.apply(prepared,verified(prepared));
        UUID otherParent=uuid(db.required("select * from delegation_grant where workflow_id=? and target_agent='KYC'",other),"id");
        assertEquals("CONSUMED",str(db.required("select * from delegation_grant where id=?",otherParent),"status"));
        UUID current=start("customer-102");
        // Select the intended KYC job without claiming the other workflow's queued Loan job.
        var lease=jobs.claim().orElseThrow();
        if("LOAN".equals(lease.phase())) lease=jobs.claim().orElseThrow();
        assertEquals("KYC",lease.phase());
        var p=kyc.prepare(lease.jobId(),lease.token()).orElseThrow();kyc.apply(p,verified(p));
        var target=queuedLoan(current);
        var before=snapshot();
        assertEquals("CONTEXT_MISMATCH",assertThrows(PolicyException.class,()->tx.execute(status->{
            db.gate();db.lockWorkflow(current);return issue(target,otherParent,clock.now());
        })).reasonCode());
        assertEquals(before,snapshot());
        assertRisk(current,10,0);assertRisk(other,10,0);
        assertEquals(0,db.query("select * from delegation_grant where target_run_id=?",target.runId()).size());
    }

    @Test void consumedApprovalIsDeniedBeforeCreatingPaymentRunGrantOrReservation() {
        UUID workflowId=ready102();var pay=approve(workflowId);
        UUID approvalId=uuid(db.required("select * from workflow_job where id=?",pay.jobId()),"approval_id");
        tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflowId);
            db.update("update approval set status='CONSUMED',consumed_at=? where id=?",clock.now(),approvalId);
        });
        long grantsBefore=count("delegation_grant"),runsBefore=count("agent_run");
        var response=payments.reserve(pay.jobId(),pay.token());
        assertEquals("DENY",response.get("decision"));assertEquals("BLOCKED",response.get("state"));
        assertEquals(List.of("APPROVAL_INVALID"),response.get("reasonCodes"));
        assertEquals(grantsBefore,count("delegation_grant"));assertEquals(runsBefore,count("agent_run"));
        assertEquals(0,count("payment_reservation"));assertEquals(0,count("mock_payment"));
        assertEquals(0,events("RESERVE"));assertEquals(0,events("CONSUME"));assertEquals(0,count("quarantine"));
        assertRisk(workflowId,35,0);
        assertEquals("CONSUMED",str(db.required("select * from approval where id=?",approvalId),"status"));
    }

    @ParameterizedTest @ValueSource(strings={"loanApplicationId","applicationId"})
    void optionalApplicationBindingAcceptsOnlyTheTrustedWorkflowApplication(String field) {
        UUID workflowId=start("customer-102");var p=prepareKyc();kyc.apply(p,verified(p));
        var target=queuedLoan(workflowId);
        UUID actual=uuid(workflow(workflowId),"application_id");
        var before=snapshot();
        // Both aliases are optional, but supplied values may not introduce another application.
        for(Object invalid:Arrays.asList(UUID.randomUUID().toString(),null,17L,"not-a-uuid",actual.toString().toUpperCase(Locale.ROOT)+" ")) {
            var action=new LinkedHashMap<String,Object>(json.map(new String(target.actionBytes(),java.nio.charset.StandardCharsets.UTF_8)));
            action.put(field,invalid);
            tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflowId);
                assertEquals("CONTEXT_MISMATCH",assertThrows(PolicyException.class,()->issueWithAction(target,json.bytes(action))).reasonCode());
            });
            assertEquals(before,snapshot());
        }
        var action=new LinkedHashMap<String,Object>(json.map(new String(target.actionBytes(),java.nio.charset.StandardCharsets.UTF_8)));
        action.put(field,actual.toString());
        var transport=tx.execute(status->{db.gate();db.lockWorkflow(workflowId);return issueWithAction(target,json.bytes(action));});
        assertEquals(workflowId,validate(target,transport,clock.now()).workflowId());
        assertRisk(workflowId,10,0);assertEquals(0,count("mock_payment"));
    }

    @ParameterizedTest @ValueSource(strings={"loanApplicationId","applicationId"})
    void authenticatedApplicationBindingIsRecheckedOnValidation(String field) {
        var fresh=freshLoan();
        var action=new LinkedHashMap<String,Object>(json.map(new String(fresh.actionBytes(),java.nio.charset.StandardCharsets.UTF_8)));
        action.put(field,UUID.randomUUID().toString());
        byte[] body=json.bytes(action);var fields=fresh.claims().canonical(json);
        fields.put("payloadHash",Json.sha256(body));
        var signed=codec.sign(json.read(json.write(fields),GrantClaims.class),body);
        assertEquals(Json.sha256(body),codec.verifyBasic(signed).claims().payloadHash());
        var before=snapshot();assertDenied("CONTEXT_MISMATCH",fresh,signed,clock.now());assertEquals(before,snapshot());
    }

    private GrantTransport issueWithAction(FreshLoan fresh,byte[] action) {
        var c=fresh.claims();return grants.issue(fresh.workflowId(),"LOAN",c.sourceRunId(),fresh.runId(),c.sourceResultId(),
                c.parentGrantId(),c.actionId(),null,c.evidenceBundleHash(),action,clock.now());
    }

    private FreshLoan freshLoan() {
        UUID workflowId=start("customer-102");var p=prepareKyc();kyc.apply(p,verified(p));
        var target=queuedLoan(workflowId);
        var transport=tx.execute(status->{db.gate();db.lockWorkflow(workflowId);
            return issue(target,target.claims().parentGrantId(),clock.now());});
        return new FreshLoan(workflowId,target.runId(),codec.verify(transport).claims(),target.actionBytes(),transport);
    }

    /** Stop at admission: normal LoanTransactions otherwise issues and consumes in one transaction. */
    private FreshLoan queuedLoan(UUID workflowId) {
        return tx.execute(status->{
            db.gate();var w=db.lockWorkflow(workflowId);
            var kycResult=db.required("select * from agent_result where id=?",uuid(w,"current_kyc_result_id"));
            UUID sourceRun=uuid(kycResult,"run_id");
            var parent=db.required("select * from delegation_grant where target_run_id=?",sourceRun);
            var job=db.required("select * from workflow_job where workflow_id=? and phase='LOAN'",workflowId);
            var app=db.required("select * from loan_application where id=?",uuid(w,"application_id"));
            UUID runId=UUID.randomUUID(),actionId=uuid(job,"execution_action_id");
            byte[] action=json.bytes(Json.ordered("workflowId",workflowId,"customerId",str(app,"customer_id"),
                    "amountKrw",number(app,"amount_krw"),"payoutAccountId",uuid(app,"payout_account_id"),
                    "originIntent",str(w,"origin_intent"),"riskLedgerId",uuid(w,"risk_ledger_id")));
            db.update("insert into agent_run(id,workflow_id,generation,role,agent_id,agent_version,run_index,status,action_id,input_bytes,input_snapshot_hash) values(?,?,?,'LOAN','LOAN',1,1,'QUEUED',?,?,?)",
                    runId,workflowId,integer(w,"generation"),actionId,action,Json.sha256(action));
            db.update("update workflow_job set run_id=? where id=?",runId,uuid(job,"id"));
            var c=new GrantClaims(UUID.randomUUID(),workflowId,integer(w,"generation"),uuid(w,"root_authorization_id"),
                    str(w,"principal_id"),str(w,"origin_intent"),"FUSE","KYC","LOAN",sourceRun,runId,LOAN_ACTION,
                    str(app,"customer_id"),number(app,"amount_krw"),uuid(app,"payout_account_id"),uuid(kycResult,"id"),
                    str(kycResult,"evidence_bundle_hash"),uuid(parent,"id"),2,actionId,Json.sha256(action),
                    str(w,"policy_version"),uuid(w,"risk_ledger_id"),null,clock.now().plusSeconds(60).toEpochMilli());
            return new FreshLoan(workflowId,runId,c,action,null);
        });
    }
    private GrantTransport issue(FreshLoan fresh,UUID parent,Instant now) {
        var c=fresh.claims();return grants.issue(fresh.workflowId(),"LOAN",c.sourceRunId(),fresh.runId(),c.sourceResultId(),
                parent,c.actionId(),null,c.evidenceBundleHash(),fresh.actionBytes(),now);
    }
    private GrantClaims validate(FreshLoan fresh,GrantTransport transport,Instant now) {
        return tx.execute(status->{db.gate();db.lockWorkflow(fresh.workflowId());
            return grants.validate(transport,"KYC",fresh.workflowId(),fresh.runId(),LOAN_ACTION,now);});
    }
    private void assertDenied(String reason,FreshLoan fresh,GrantTransport transport,Instant now) {
        // Commit the transaction after the denial: rollback must not hide accidental attribution writes.
        tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(fresh.workflowId());
            assertEquals(reason,assertThrows(PolicyException.class,()->grants.validate(transport,"KYC",
                    fresh.workflowId(),fresh.runId(),LOAN_ACTION,now)).reasonCode());
        });
    }
    private UUID startCustomerFromRegistry(String customer) {
        var app=db.required("select * from application_registry where customer_id=?",customer);
        return (UUID)workflows.start(new Actor(customer,"CUSTOMER",Set.of(customer)),UUID.randomUUID(),
                new StartWorkflowRequest(str(app,"business_reference"),customer,number(app,"amount_krw"),uuid(app,"payout_account_id"))).get("workflowId");
    }
    private Map<String,String> snapshot() {
        var result=new LinkedHashMap<String,String>();
        for(String table:List.of("workflow","workflow_job","agent_run","agent_result","delegation_grant","risk_ledger",
                "workflow_stage","quarantine","approval","payment_reservation","mock_payment","run_dependency"))
            result.put(table,db.required("select coalesce(jsonb_agg(row_data order by row_data::text),'[]'::jsonb)::text as data from (select to_jsonb(t) row_data from "+table+" t) s").get("data").toString());
        return result;
    }
    private record FreshLoan(UUID workflowId,UUID runId,GrantClaims claims,byte[] actionBytes,GrantTransport transport) {}
}
