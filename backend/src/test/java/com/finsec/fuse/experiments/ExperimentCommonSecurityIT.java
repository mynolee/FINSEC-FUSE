package com.finsec.fuse.experiments;

import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.payment.ApprovalRequest;
import com.finsec.fuse.payment.ApprovalService;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.persistence.TimeSource;
import com.finsec.fuse.policy.*;
import com.finsec.fuse.testing.PostgresSupport;
import com.finsec.fuse.workflow.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.transaction.support.TransactionTemplate;
import static org.junit.jupiter.api.Assertions.*;

/** Real service/database parity: shared integrity and staff RBAC survive the FUSE ablations. */
class ExperimentCommonSecurityIT {
    @ParameterizedTest @ValueSource(booleans={true,false})
    void commonChecksDenyWithoutDownstreamExecutionAndOnlyBaselineOmitsScope(boolean baseline) {
        var database=new ExperimentSandbox.Database(PostgresSupport.url(),"postgres","");
        try(var sandbox=ExperimentSandbox.open(database,baseline)) {
            var db=sandbox.bean(Db.class);var json=sandbox.bean(Json.class);var tx=sandbox.bean(TransactionTemplate.class);
            var service=sandbox.bean(DelegationService.class);var codec=sandbox.bean(GrantCodec.class);
            assertEquals(baseline,service instanceof BaselineDelegationService);
            UUID workflow=(UUID)sandbox.bean(WorkflowService.class).start(new Actor("customer-102","CUSTOMER",Set.of("customer-102")),UUID.randomUUID(),
                new StartWorkflowRequest("APP-DEMO-102-001","customer-102",1_000_000L,UUID.fromString("00000000-0000-4000-8000-000000000102"))).get("workflowId");
            var job=sandbox.bean(JobTransactions.class).claim().orElseThrow();
            var prepared=sandbox.bean(KycTransactions.class).prepare(job.jobId(),job.token()).orElseThrow();
            var row=db.required("SELECT * FROM delegation_grant WHERE target_run_id=?",prepared.input().runId());
            var original=service.transport(Db.uuid(row,"id"));var claims=codec.verify(original).claims();
            // Isolate the scope comparison from consumed-token rejection; the real KYC start already succeeded.
            tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflow);
                db.update("UPDATE delegation_grant SET status='ISSUED' WHERE id=?",claims.grantId());
            });
            byte[] wrongMac=Base64.getUrlDecoder().decode(original.grant().macBase64Url());wrongMac[0]^=1;
            var badMac=new GrantTransport(new GrantTransport.Grant(original.grant().format(),original.grant().kid(),original.grant().payloadBase64Url(),b64(wrongMac)),original.actionPayloadBase64Url());
            var alteredBody=new GrantTransport(original.grant(),b64("{}".getBytes(StandardCharsets.UTF_8)));
            byte[] duplicate="{\"amountKrw\":1000000,\"amountKrw\":2000000}".getBytes(StandardCharsets.UTF_8);
            var fields=claims.canonical(json);fields.put("payloadHash",Json.sha256(duplicate));
            var badJson=codec.sign(json.read(json.bytes(fields),GrantClaims.class),duplicate);
            var now=sandbox.bean(TimeSource.class).now();
            for(var invalid:List.of(badMac,alteredBody,badJson)) {
                var denial=assertThrows(PolicyException.class,()->tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflow);
                    service.validate(invalid,"FUSE",workflow,prepared.input().runId(),"EVALUATE_KYC",now);
                }));
                assertEquals("SIGNATURE_INVALID",denial.reasonCode());
                assertNoDownstream(db);
            }
            var approvals=sandbox.bean(ApprovalService.class);
            var roleDenial=assertThrows(ApiException.class,()->approvals.decide(new Actor("mock-kyc","KYC",Set.of("customer-102")),workflow,UUID.randomUUID(),
                new ApprovalRequest(ApprovalRequest.Decision.APPROVE,"0".repeat(64),"Forged reviewer request")));
            assertEquals(403,roleDenial.status());assertNoDownstream(db);
            if(baseline) {
                assertDoesNotThrow(()->tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflow);
                    service.validate(original,"FUSE",workflow,prepared.input().runId(),"FINAL_APPROVE",now);
                }));
            } else {
                var scopeDenial=assertThrows(PolicyException.class,()->tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflow);
                    service.validate(original,"FUSE",workflow,prepared.input().runId(),"FINAL_APPROVE",now);
                }));
                assertEquals("SCOPE_EXCEEDED",scopeDenial.reasonCode());
            }
            assertNoDownstream(db);
            assertEquals("RUNNING",Db.string(db.required("SELECT status FROM agent_run WHERE id=?",prepared.input().runId()),"status"));
            assertEquals("KYC_PENDING",Db.string(db.required("SELECT state FROM workflow WHERE id=?",workflow),"state"));
        }
    }
    private static void assertNoDownstream(Db db) {
        for(String table:List.of("mock_payment","approval","payment_reservation","run_dependency","quarantine"))
            assertEquals(0,Db.integer(db.required("SELECT count(*) n FROM "+table),"n"),table);
        assertEquals(0,Db.integer(db.required("SELECT count(*) n FROM agent_run WHERE role IN ('LOAN','PAYMENT')"),"n"));
        assertEquals(0,Db.integer(db.required("SELECT count(*) n FROM risk_ledger WHERE event_type IN ('RESERVE','CONSUME')"),"n"));
    }
    private static String b64(byte[] bytes) { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
}
