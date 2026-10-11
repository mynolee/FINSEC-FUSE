package com.finsec.fuse.policy;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.JsonConfiguration;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

class EnvelopeValidatorTest {
    private final Instant now=Instant.parse("2026-10-09T04:00:00Z");
    private final Json json=new Json(new JsonConfiguration().jsonMapper());
    private final GrantCodec codec=new GrantCodec(json,new SigningKeyProvider("test",Map.of("test",new byte[32])));
    private final EnvelopeValidator validator=new EnvelopeValidator();
    private final byte[] action=json.bytes(Map.of("action","EVALUATE_KYC"));
    private final UUID workflow=UUID.randomUUID(),root=UUID.randomUUID(),run=UUID.randomUUID(),account=UUID.randomUUID(),actionId=UUID.randomUUID(),ledger=UUID.randomUUID();
    private GrantClaims rootClaims() {return new GrantClaims(UUID.randomUUID(),workflow,1,root,"principal-102","LOAN_APPLICATION","FUSE","FUSE","KYC",null,run,"EVALUATE_KYC","customer-102",1_000_000,account,null,null,null,1,actionId,Json.sha256(action),"FUSE-MVP-2",ledger,null,now.plusSeconds(60).toEpochMilli());}
    private EnvelopeValidator.WorkflowBinding binding() { return new EnvelopeValidator.WorkflowBinding(workflow,1,root,"principal-102","LOAN_APPLICATION","customer-102",1_000_000,account,"FUSE-MVP-2",ledger); }
    private EnvelopeValidator.RunBinding target() { return new EnvelopeValidator.RunBinding(run,workflow,1,"KYC","QUEUED",actionId); }
    private EnvelopeValidator.StoredGrant stored(GrantCodec.VerifiedGrant verified,String status) { return new EnvelopeValidator.StoredGrant(verified.claims(),verified.kid(),status,verified.claimsBytes(),verified.actionBytes(),verified.macBytes()); }
    @Test void normalQueuedRunMayStartWithoutAnAlreadyExistingDependency() {
        var verified=codec.verify(codec.sign(rootClaims(),action));
        assertDoesNotThrow(()->validator.validate(verified,stored(verified,"ISSUED"),binding(),target(),"FUSE","EVALUATE_KYC",now));
    }
    @Test void currentGrantExpiryIsExclusive() {
        var verified=codec.verify(codec.sign(rootClaims(),action));
        assertEquals("GRANT_EXPIRED",assertThrows(PolicyException.class,()->validator.validate(verified,stored(verified,"ISSUED"),binding(),target(),"FUSE","EVALUATE_KYC",now.plusSeconds(60))).reasonCode());
    }
    @Test void historicConsumedGrantCannotStartFreshWork() {
        var verified=codec.verify(codec.sign(rootClaims(),action));
        assertEquals("SCOPE_EXCEEDED",assertThrows(PolicyException.class,()->validator.validate(verified,stored(verified,"CONSUMED"),binding(),target(),"FUSE","EVALUATE_KYC",now)).reasonCode());
    }
    @Test void principalAndSubjectAreDifferentBindings() {
        var verified=codec.verify(codec.sign(rootClaims(),action));
        var wrong=new EnvelopeValidator.WorkflowBinding(workflow,1,root,"customer-102","LOAN_APPLICATION","customer-102",1_000_000,account,"FUSE-MVP-2",ledger);
        assertEquals("CONTEXT_MISMATCH",assertThrows(PolicyException.class,()->validator.validate(verified,stored(verified,"ISSUED"),wrong,target(),"FUSE","EVALUATE_KYC",now)).reasonCode());
    }
    @ParameterizedTest @ValueSource(strings={"workflow","root","principal","intent","customer","amount","account","policy","ledger","generation"})
    void signedClaimsDoNotOverrideLiveApplication(String field) {
        var verified=codec.verify(codec.sign(rootClaims(),action));
        var w=new EnvelopeValidator.WorkflowBinding(field.equals("workflow")?UUID.randomUUID():workflow,field.equals("generation")?2:1,
                field.equals("root")?UUID.randomUUID():root,field.equals("principal")?"other":"principal-102",
                field.equals("intent")?"OTHER":"LOAN_APPLICATION",field.equals("customer")?"customer-101":"customer-102",
                field.equals("amount")?2_000_000:1_000_000,field.equals("account")?UUID.randomUUID():account,
                field.equals("policy")?"FUSE-MVP-OTHER":"FUSE-MVP-2",field.equals("ledger")?UUID.randomUUID():ledger);
        assertEquals(field.equals("generation")?"STALE_GENERATION":"CONTEXT_MISMATCH",assertThrows(PolicyException.class,
                ()->validator.validate(verified,stored(verified,"ISSUED"),w,target(),"FUSE","EVALUATE_KYC",now)).reasonCode());
    }
    @Test void registryBytesAreRequiredEvenForCorrectMac() {
        var verified=codec.verify(codec.sign(rootClaims(),action));var altered=verified.actionBytes();altered[0]^=1;
        var registry=new EnvelopeValidator.StoredGrant(verified.claims(),verified.kid(),"ISSUED",verified.claimsBytes(),altered,verified.macBytes());
        assertEquals("SIGNATURE_INVALID",assertThrows(PolicyException.class,()->validator.validate(verified,registry,binding(),target(),"FUSE","EVALUATE_KYC",now)).reasonCode());
    }
    @Test void grantCannotBorrowAnotherRoleOrAction() {
        var v=codec.verify(codec.sign(rootClaims(),action));
        assertEquals("SCOPE_EXCEEDED",assertThrows(PolicyException.class,()->validator.validate(v,stored(v,"ISSUED"),binding(),target(),"KYC","EVALUATE_KYC",now)).reasonCode());
        assertEquals("SCOPE_EXCEEDED",assertThrows(PolicyException.class,()->validator.validate(v,stored(v,"ISSUED"),binding(),target(),"FUSE","EXECUTE_MOCK_PAYMENT",now)).reasonCode());
    }
    @ParameterizedTest @ValueSource(strings={"FINAL_APPROVE","EXECUTE_MOCK_PAYMENT","EVALUATE_KYC"})
    void kycCanOnlyCreateLoanRecommendation(String requested) {
        var c=rootClaims();var attack=new GrantClaims(c.grantId(),workflow,1,root,c.principal(),c.originIntent(),"FUSE","KYC","LOAN",UUID.randomUUID(),run,
                requested,c.customerId(),c.amountKrw(),account,UUID.randomUUID(),"a".repeat(64),UUID.randomUUID(),2,actionId,c.payloadHash(),c.policyVersion(),ledger,null,c.expiresAtEpochMs());
        assertEquals("SCOPE_EXCEEDED",assertThrows(PolicyException.class,()->EnvelopeValidator.requireEdge(attack)).reasonCode());
    }
    @Test void paymentRequiresIndependentApprovalAndParent() {
        var c=rootClaims();var attack=new GrantClaims(c.grantId(),workflow,1,root,c.principal(),c.originIntent(),"FUSE","LOAN","PAYMENT",UUID.randomUUID(),run,
                "EXECUTE_MOCK_PAYMENT",c.customerId(),c.amountKrw(),account,UUID.randomUUID(),"a".repeat(64),UUID.randomUUID(),3,actionId,c.payloadHash(),c.policyVersion(),ledger,null,c.expiresAtEpochMs());
        assertEquals("SCOPE_EXCEEDED",assertThrows(PolicyException.class,()->EnvelopeValidator.requireEdge(attack)).reasonCode());
    }
}
