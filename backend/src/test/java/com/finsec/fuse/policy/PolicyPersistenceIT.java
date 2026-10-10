package com.finsec.fuse.policy;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.*;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.testing.PostgresSupport;
import java.time.Instant;
import java.util.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import static org.junit.jupiter.api.Assertions.*;

/** Real PostgreSQL tests of registry bindings, consumed ancestry and source-version propagation. */
class PolicyPersistenceIT {
    private static final Instant NOW=Instant.parse("2026-10-09T04:00:00Z");
    private Db db;private Json json;private FusePolicy policy;private EvidenceValidator evidence;
    private QuarantineMatcher matcher;private DelegationService delegations;private GrantCodec codec;
    private final UUID workflow=UUID.randomUUID(),account=UUID.randomUUID(),application=UUID.randomUUID();
    private final UUID kyc=UUID.randomUUID(),loan=UUID.randomUUID(),payment=UUID.randomUUID();
    private final UUID kycResult=UUID.randomUUID(),loanResult=UUID.randomUUID(),document=UUID.randomUUID();
    private final UUID idEvidence=UUID.randomUUID(),faceEvidence=UUID.randomUUID();
    private UUID kycGrant,loanGrant;private String bundle;
    @BeforeEach void schema() throws Exception {
        String name="policy_"+UUID.randomUUID().toString().replace("-","");
        var admin=new JdbcTemplate(new DriverManagerDataSource(PostgresSupport.url(),"postgres",""));admin.execute("CREATE SCHEMA "+name);
        String url=PostgresSupport.url()+(PostgresSupport.url().contains("?")?"&":"?")+"currentSchema="+name;
        var dataSource=new DriverManagerDataSource(url,"postgres","");
        Flyway.configure().dataSource(dataSource).locations("classpath:db/migration").load().migrate();
        db=new Db(new JdbcTemplate(dataSource));var config=new JsonConfiguration();json=new Json(config.jsonMapper());policy=config.fusePolicy(json.mapper());
        evidence=new EvidenceValidator(db,policy,json);matcher=new QuarantineMatcher(db);
        codec=new GrantCodec(json,new SigningKeyProvider("test",Map.of("test",new byte[32])));
        delegations=new DelegationService(db,json,policy,codec,new EnvelopeValidator(),evidence,matcher);
        for(String agent:List.of("FUSE","KYC","LOAN","PAYMENT")) db.update("INSERT INTO agent_registry(agent_id,version,role,auth_subject) VALUES(?,1,?,?)",agent,agent.equals("FUSE")?"FUSE_WORKER":agent,agent.toLowerCase());
        db.update("INSERT INTO mock_account(id,customer_id) VALUES(?,'customer-102')",account);
        db.update("INSERT INTO source_document_version(document_id,version,content,content_hash) VALUES(?,1,'safe',?),(?,2,'tainted',?)",document,"a".repeat(64),document,"b".repeat(64));
        db.update("INSERT INTO application_registry VALUES('POLICY-TEST','customer-102',1000000,?,?,1)",account,document);
        db.update("INSERT INTO loan_application(id,business_reference,customer_id,amount_krw,payout_account_id) VALUES(?,'POLICY-TEST','customer-102',1000000,?)",application,account);
        db.update("INSERT INTO workflow(id,application_id,root_authorization_id,risk_ledger_id,principal_id,policy_version,state) VALUES(?,?,?,?,'customer-102','FUSE-MVP-2','KYC_PENDING')",workflow,application,UUID.randomUUID(),UUID.randomUUID());
        for(String stage:List.of("KYC","LOAN","PAYMENT"))db.update("INSERT INTO workflow_stage(workflow_id,stage) VALUES(?,?)",workflow,stage);
        addEvidence(idEvidence,"ID_DOC","mock-id-issuer");addEvidence(faceEvidence,"FACE_MATCH","mock-face-issuer");
        addRun(kyc,"KYC");
        db.update("INSERT INTO run_evidence_use VALUES(?,?),(?,?)",kyc,idEvidence,kyc,faceEvidence);
    }
    private void addEvidence(UUID id,String kind,String issuer) {
        var original=Json.ordered("customerId","customer-102","evidenceType",kind,"issuerId",issuer,"outcome","PASS","issuedAt",NOW.minusSeconds(300).toString(),"expiresAt",NOW.plusSeconds(1800).toString());
        db.update("INSERT INTO trusted_evidence(id,customer_id,evidence_type,issuer_id,version,outcome,original_json,original_hash,status,issued_at,expires_at) VALUES(?,'customer-102',?,?,1,'PASS',?,?,'ACTIVE',?,?)",id,kind,issuer,json.write(original),json.hash(original),NOW.minusSeconds(300),NOW.plusSeconds(1800));
    }
    private void addRun(UUID id,String role) {db.update("INSERT INTO agent_run(id,workflow_id,generation,role,agent_id,agent_version,run_index,status,action_id) VALUES(?,?,1,?,?,1,1,'QUEUED',?)",id,workflow,role,role,UUID.randomUUID());}
    private UUID action(UUID run) {return Db.uuid(db.required("SELECT action_id FROM agent_run WHERE id=?",run),"action_id");}
    private GrantTransport issue(String role,UUID source,UUID target,UUID result,UUID parent,UUID approval,Instant now) {
        return delegations.issue(workflow,role,source,target,result,parent,action(target),approval,bundle,json.bytes(Map.of("workflowId",workflow,"amountKrw",1_000_000)),now);
    }
    private void finishKyc() {
        var grant=issue("KYC",null,kyc,null,null,null,NOW);
        kycGrant=delegations.validate(grant,"FUSE",workflow,kyc,"EVALUATE_KYC",NOW).grantId();delegations.consume(kycGrant,NOW);
        var result=evidence.validate("VERIFIED",List.of(idEvidence,faceEvidence),kyc,"customer-102",NOW);assertTrue(result.validated());bundle=result.evidenceBundleHash();
        var body=Json.ordered("status","VERIFIED","evidenceIds",List.of(idEvidence,faceEvidence),"explanation","Independent checks passed");
        db.update("UPDATE agent_run SET status='VALIDATED',started_at=? WHERE id=?",NOW,kyc);
        db.update("INSERT INTO agent_result(id,run_id,workflow_id,generation,status,body_json,result_hash,evidence_bundle_hash) VALUES(?,?,?,1,'VALIDATED',?::jsonb,?,?)",kycResult,kyc,workflow,json.write(body),json.hash(body),bundle);
        db.update("UPDATE workflow SET current_kyc_result_id=?,used_risk=10,state='KYC_VALIDATED' WHERE id=?",kycResult,workflow);
        db.update("UPDATE workflow_stage SET used_points=10,run_count=1 WHERE workflow_id=? AND stage='KYC'",workflow);
    }
    private void finishLoan(Instant time) {
        finishKyc();addRun(loan,"LOAN");var grant=issue("LOAN",kyc,loan,kycResult,kycGrant,null,time);
        loanGrant=delegations.validate(grant,"KYC",workflow,loan,"CREATE_LOAN_RECOMMENDATION",time).grantId();delegations.consume(loanGrant,time);
        db.update("INSERT INTO run_dependency VALUES(?,?,?,?,1)",kyc,loan,kycResult,workflow);
        db.update("UPDATE agent_run SET status='VALIDATED',started_at=? WHERE id=?",time,loan);
        var body=Map.of("recommendation","APPROVE_RECOMMENDED");
        db.update("INSERT INTO agent_result(id,run_id,workflow_id,generation,status,body_json,result_hash,evidence_bundle_hash) VALUES(?,?,?,1,'VALIDATED',?::jsonb,?,?)",loanResult,loan,workflow,json.write(body),json.hash(body),bundle);
        db.update("UPDATE workflow SET current_loan_result_id=?,used_risk=35,state='WAIT_APPROVAL' WHERE id=?",loanResult,workflow);
        db.update("UPDATE workflow_stage SET used_points=25,run_count=1 WHERE workflow_id=? AND stage='LOAN'",workflow);
    }
    private UUID approval(Instant time) {
        UUID id=UUID.randomUUID();String hash=Db.string(db.required("SELECT result_hash FROM agent_result WHERE id=?",loanResult),"result_hash");
        db.update("""
          INSERT INTO approval(id,workflow_id,generation,actor_id,customer_id,amount_krw,payout_account_id,
           kyc_result_id,loan_result_id,loan_result_hash,evidence_bundle_hash,policy_version,review_snapshot_hash,
           extra_risk,risk_limit,status,expires_at) VALUES(?,?,1,'staff-01','customer-102',1000000,?,?,?,?,?,'FUSE-MVP-2',?,45,85,'AVAILABLE',?)
          """,id,workflow,account,kycResult,loanResult,hash,bundle,"c".repeat(64),time.plusSeconds(600));return id;
    }
    @Test void storedEvidenceRevalidationDetectsRevocationDespiteUnchangedHash() {
        finishKyc();assertTrue(evidence.validateStored(kycResult,NOW).validated());
        db.update("UPDATE trusted_evidence SET status='REVOKED',revoked_at=? WHERE id=?",NOW,faceEvidence);
        assertEquals("EVIDENCE_INVALID",evidence.validateStored(kycResult,NOW).reasonCode());
    }
    @Test void expiredConsumedKycGrantStillSupportsLaterLoanStart() {finishLoan(NOW.plusSeconds(120));assertNotNull(loanGrant);}
    @Test void exactGrantRegistryColumnsCannotBeChangedAfterMac() {
        var grant=issue("KYC",null,kyc,null,null,null,NOW);var id=codec.verify(grant).claims().grantId();
        db.update("UPDATE delegation_grant SET amount_krw=2000000 WHERE id=?",id);
        assertEquals("SIGNATURE_INVALID",assertThrows(PolicyException.class,()->delegations.validate(grant,"FUSE",workflow,kyc,"EVALUATE_KYC",NOW)).reasonCode());
    }
    @Test void sameActionCannotBeReissuedAfterGrantExpiration() {
        issue("KYC",null,kyc,null,null,null,NOW);
        assertEquals("SCOPE_EXCEEDED",assertThrows(PolicyException.class,()->issue("KYC",null,kyc,null,null,null,NOW.plusSeconds(61))).reasonCode());
    }
    @Test void paymentRequiresActualLoanDependencyNotClaimsPath() {
        finishLoan(NOW);addRun(payment,"PAYMENT");UUID approval=approval(NOW);
        db.update("DELETE FROM run_dependency WHERE child_run_id=?",loan);
        assertEquals("CONTEXT_MISMATCH",assertThrows(PolicyException.class,()->issue("PAYMENT",loan,payment,loanResult,loanGrant,approval,NOW)).reasonCode());
    }
    @Test void paymentRechecksCurrentEvidenceAndExactApproval() {
        finishLoan(NOW);addRun(payment,"PAYMENT");UUID approval=approval(NOW);var grant=issue("PAYMENT",loan,payment,loanResult,loanGrant,approval,NOW);
        assertNotNull(delegations.validate(grant,"LOAN",workflow,payment,"EXECUTE_MOCK_PAYMENT",NOW));
        db.update("UPDATE approval SET amount_krw=2000000 WHERE id=?",approval);
        assertEquals("APPROVAL_INVALID",assertThrows(PolicyException.class,()->delegations.validate(grant,"LOAN",workflow,payment,"EXECUTE_MOCK_PAYMENT",NOW)).reasonCode());
    }
    @Test void paymentExpiryUsesTrustedApprovalDespiteRequestBodyTtlHints() {
        finishLoan(NOW);addRun(payment,"PAYMENT");UUID approval=approval(NOW);
        Instant trustedDeadline=NOW.plusSeconds(20);
        db.update("UPDATE approval SET expires_at=? WHERE id=?",trustedDeadline,approval);
        byte[] body=json.bytes(Map.of("workflowId",workflow,"amountKrw",1_000_000,"grantTtlSeconds",3600,
                "expiresAtEpochMs",NOW.plusSeconds(3600).toEpochMilli()));
        var transport=delegations.issue(workflow,"PAYMENT",loan,payment,loanResult,loanGrant,action(payment),approval,bundle,body,NOW);
        var claims=codec.verify(transport).claims();
        assertEquals(trustedDeadline.toEpochMilli(),claims.expiresAtEpochMs());
        assertEquals(trustedDeadline,Db.instant(db.required("SELECT expires_at FROM delegation_grant WHERE id=?",claims.grantId()),"expires_at"));
    }
    @Test void sourceVersionQuarantinePropagatesAlongEveryActualAncestor() {
        finishLoan(NOW);addRun(payment,"PAYMENT");
        db.update("INSERT INTO run_dependency VALUES(?,?,?,?,1)",loan,payment,loanResult,workflow);
        db.update("INSERT INTO run_source_use VALUES(?,?,2,?)",kyc,document,"b".repeat(64));
        db.update("INSERT INTO quarantine(id,scope,document_id,document_version,status,reason_code,actor_id,gate_epoch) VALUES(?,'SOURCE_VERSION',?,1,'ACTIVE','EVIDENCE_INVALID','security-01',1)",UUID.randomUUID(),document);
        assertFalse(matcher.isQuarantined(payment));
        db.update("INSERT INTO quarantine(id,scope,document_id,document_version,status,reason_code,actor_id,gate_epoch) VALUES(?,'SOURCE_VERSION',?,2,'ACTIVE','EVIDENCE_INVALID','security-01',2)",UUID.randomUUID(),document);
        assertTrue(matcher.isQuarantined(kyc));assertTrue(matcher.isQuarantined(loan));assertTrue(matcher.isQuarantined(payment));assertTrue(matcher.workflowQuarantined(workflow));
    }
}
