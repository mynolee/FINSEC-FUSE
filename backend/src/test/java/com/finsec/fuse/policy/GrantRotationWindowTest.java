package com.finsec.fuse.policy;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.JsonConfiguration;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Cryptographic verification plus the real execution-envelope validator, using an explicit DB-time input.
 * Historical receipt recovery is a separate PostgreSQL oracle:
 * payment/PaymentIdempotencyIT.lostSuccessResponseIsHistoricalEvenAfterApprovalAndEvidenceExpiry.
 * This unit suite does not claim to exercise that database path or automatic key retirement.
 */
class GrantRotationWindowTest {
    private final Json json=new Json(new JsonConfiguration().jsonMapper());
    private final Instant issuedAt=Instant.parse("2026-10-09T04:00:00Z");
    private final byte[] oldKey=randomKey(),newKey=randomKey();
    private final UUID workflow=UUID.randomUUID(),root=UUID.randomUUID(),run=UUID.randomUUID(),
            account=UUID.randomUUID(),actionId=UUID.randomUUID(),ledger=UUID.randomUUID();
    private final byte[] action=json.bytes(Map.of("allowedAction","EVALUATE_KYC"));
    private final GrantClaims claims=new GrantClaims(UUID.randomUUID(),workflow,1,root,"principal-102",
            "LOAN_APPLICATION","FUSE","FUSE","KYC",null,run,"EVALUATE_KYC","customer-102",1_000_000,
            account,null,null,null,1,actionId,Json.sha256(action),"FUSE-MVP-2",ledger,null,issuedAt.plusSeconds(60).toEpochMilli());
    private final GrantCodec original=new GrantCodec(json,new SigningKeyProvider("old",Map.of("old",oldKey)));
    private final GrantTransport issued=original.sign(claims,action);
    private final GrantCodec.VerifiedGrant originalVerified=original.verify(issued);
    private final EnvelopeValidator.StoredGrant stored=new EnvelopeValidator.StoredGrant(claims,"old","ISSUED",
            originalVerified.claimsBytes(),originalVerified.actionBytes(),originalVerified.macBytes());
    private final EnvelopeValidator.WorkflowBinding binding=new EnvelopeValidator.WorkflowBinding(workflow,1,root,
            "principal-102","LOAN_APPLICATION","customer-102",1_000_000,account,"FUSE-MVP-2",ledger);
    private final EnvelopeValidator.RunBinding target=new EnvelopeValidator.RunBinding(run,workflow,1,"KYC","QUEUED",actionId);

    @Test void oldIssuingGrantRemainsExecutableUntilItsOriginalDeadlineAfterRotation() {
        assertDoesNotThrow(()->validate(original,issuedAt));
        GrantCodec rotated=rotated(SigningKeyProvider.State.VERIFY_ONLY);
        assertEquals("new",rotated.sign(claims,action).grant().kid());
        assertEquals("old",rotated.verify(issued).kid());
        assertArrayEquals(originalVerified.macBytes(),rotated.verify(issued).macBytes());
        assertDoesNotThrow(()->validate(rotated,issuedAt.plusMillis(59_999)));
        assertEquals(issuedAt.plusSeconds(60).toEpochMilli(),rotated.verify(issued).claims().expiresAtEpochMs());
    }

    @ParameterizedTest @ValueSource(longs={60_000,60_001,120_000})
    void verificationOnlyNeverExtendsTheOriginalExecutionWindow(long elapsedMillis) {
        GrantCodec rotated=rotated(SigningKeyProvider.State.VERIFY_ONLY);
        // A valid MAC is not sufficient authority: expiry is checked against authoritative time.
        assertDoesNotThrow(()->rotated.verify(issued));
        var failure=assertThrows(PolicyException.class,()->validate(rotated,issuedAt.plusMillis(elapsedMillis)));
        assertEquals("GRANT_EXPIRED",failure.reasonCode());
    }

    @Test void revokedOldKeyRejectsAuthenticGrantImmediatelyBeforeItsDeadline() {
        assertDoesNotThrow(()->validate(rotated(SigningKeyProvider.State.VERIFY_ONLY),issuedAt.plusSeconds(1)));
        GrantCodec revoked=rotated(SigningKeyProvider.State.REVOKED);
        assertEquals("SIGNATURE_INVALID",assertThrows(PolicyException.class,
                ()->validate(revoked,issuedAt.plusSeconds(1))).reasonCode());
        assertEquals("new",revoked.verify(revoked.sign(claims,action)).kid());
    }

    private void validate(GrantCodec codec,Instant dbNow) {
        new EnvelopeValidator().validate(codec.verify(issued),stored,binding,target,"FUSE","EVALUATE_KYC",dbNow);
    }
    private GrantCodec rotated(SigningKeyProvider.State oldState) {
        return new GrantCodec(json,new SigningKeyProvider("new",Map.of(
                "old",new SigningKeyProvider.Entry(oldKey,oldState),
                "new",new SigningKeyProvider.Entry(newKey,SigningKeyProvider.State.ISSUING)),true));
    }
    private static byte[] randomKey(){byte[] bytes=new byte[32];new SecureRandom().nextBytes(bytes);return bytes;}
}
