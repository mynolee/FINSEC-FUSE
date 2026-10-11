package com.finsec.fuse.config;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.persistence.TimeSource;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

@Component
@Profile({"demo","test"})
@Order(Ordered.HIGHEST_PRECEDENCE)
@ConditionalOnProperty(name="fuse.demo-seed",havingValue="true",matchIfMissing=true)
public final class DemoSeed implements ApplicationRunner {
    public record Document(int version,String contentId,boolean reviewedSafe) {}
    public record Evidence(UUID id,String type,String issuerId,String outcome) {}
    public record Customer(String customerId,UUID accountId,long monthlyIncomeKrw,long maxLoanAmountKrw,long amountKrw,String businessReference,int documentVersion,List<Evidence> evidence) {}
    public record Fixture(String fixtureSetId,String loanPolicyVersion,UUID documentId,List<Document> documents,List<Customer> customers) {}
    private final Db db;private final Json json;private final TimeSource time;private final TransactionTemplate tx;private final PrivateDocuments documents;
    public DemoSeed(Db db,Json json,TimeSource time,TransactionTemplate tx,PrivateDocuments documents) {this.db=db;this.json=json;this.time=time;this.tx=tx;this.documents=documents;}
    @Override public void run(ApplicationArguments ignored) throws Exception {
        Fixture fixture;
        try(var in=new ClassPathResource("fixtures/demo_seed.json").getInputStream()) {fixture=json.read(in.readAllBytes(),Fixture.class);}
        tx.executeWithoutResult(status->seed(fixture));
    }
    public void seed(Fixture fixture) {
        db.gate(); Instant now=time.now();
        String[][] agents={{"FUSE","FUSE_WORKER","fuse-worker"},{"KYC","KYC","kyc-service"},{"LOAN","LOAN","loan-agent"},{"PAYMENT","PAYMENT","payment-agent"}};
        for(String[] agent:agents)db.update("INSERT INTO agent_registry(agent_id,version,role,auth_subject,status) VALUES(?,1,?,?,'ACTIVE') ON CONFLICT DO NOTHING",agent[0],agent[1],agent[2]);
        for(Document document:fixture.documents()) {
            String content=documents.resolve(document.contentId(),documents.liveMode());
            db.update("INSERT INTO source_document_version(document_id,version,content,content_hash,reviewed_safe,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                fixture.documentId(),document.version(),content,Json.sha256(content.getBytes(StandardCharsets.UTF_8)),document.reviewedSafe(),now);
        }
        for(Customer customer:fixture.customers()) {
            db.update("INSERT INTO mock_account(id,customer_id,status) VALUES(?,?,'ACTIVE') ON CONFLICT DO NOTHING",customer.accountId(),customer.customerId());
            String profileHash=json.hash(Json.ordered("customerId",customer.customerId(),"monthlyIncomeKrw",customer.monthlyIncomeKrw(),"maxLoanAmountKrw",customer.maxLoanAmountKrw()));
            db.update("INSERT INTO mock_profile(customer_id,monthly_income_krw,max_loan_amount_krw,profile_hash,policy_version) VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING",
                customer.customerId(),customer.monthlyIncomeKrw(),customer.maxLoanAmountKrw(),profileHash,fixture.loanPolicyVersion());
            db.update("INSERT INTO application_registry(business_reference,customer_id,amount_krw,payout_account_id,document_id,document_version) VALUES(?,?,?,?,?,?) ON CONFLICT DO NOTHING",
                customer.businessReference(),customer.customerId(),customer.amountKrw(),customer.accountId(),fixture.documentId(),customer.documentVersion());
            for(Evidence evidence:customer.evidence()) {
                Instant issued=now.minusSeconds(300),expires=now.plusSeconds(1800);
                var original=Json.ordered("customerId",customer.customerId(),"evidenceType",evidence.type(),"issuerId",evidence.issuerId(),"outcome",evidence.outcome(),"issuedAt",issued.toString(),"expiresAt",expires.toString());
                db.update("INSERT INTO trusted_evidence(id,customer_id,evidence_type,issuer_id,version,outcome,original_json,original_hash,status,issued_at,expires_at) VALUES(?,?,?,?,1,?,?,?,'ACTIVE',?,?) ON CONFLICT DO NOTHING",
                    evidence.id(),customer.customerId(),evidence.type(),evidence.issuerId(),evidence.outcome(),json.write(original),json.hash(original),issued,expires);
            }
        }
    }
}
