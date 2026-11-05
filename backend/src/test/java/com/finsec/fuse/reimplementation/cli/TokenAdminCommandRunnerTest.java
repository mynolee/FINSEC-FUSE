package com.finsec.fuse.reimplementation.cli;

import com.finsec.fuse.auth.DemoTokenProvisioner;
import com.finsec.fuse.reimplementation.auth.*;
import com.finsec.fuse.reimplementation.persistence.JdbcTokenIssuanceWriter;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TokenAdminCommandRunnerTest {
    private static final String CANARY="synthetic-private-driver-canary";
    private static String[] issue(){return new String[]{"issue","--schema","synthetic","--credential-input-fd","3",
            "--actor","synthetic-admin-target","--role","CUSTOMER","--scope","customer-one","--credential-output-fd","4"};}
    private static final class Session implements TokenAdminCommandRunner.NativeAdminSession {
        final List<String> events=new ArrayList<>();
        JdbcTokenIssuanceWriter.Outcome stored=JdbcTokenIssuanceWriter.Outcome.INSERT_CONFIRMED;
        JdbcTokenIssuanceWriter.Cleanup dbCleanup=JdbcTokenIssuanceWriter.Cleanup.CONFIRMED;
        TokenIssuanceOutcomeProjector.Delivery delivery=TokenIssuanceOutcomeProjector.Delivery.COMPLETE;
        TokenAdminCommandRunner.ChannelCleanup cleanup=TokenAdminCommandRunner.ChannelCleanup.CONFIRMED;
        String fail="";int fill=32;int checks;byte[] rawAlias,wireAlias,fingerprintAlias;String delivered;boolean mismatch;
        public TokenAdminCommandRunner.IssuePlan prepareIssue(TokenAdminArguments.Issue c){
            events.add("plan");if(fail.equals("plan"))throw new TokenAdminCommandRunner.AdmissionRefused();
            Instant t=Instant.parse("2030-01-01T00:00:00Z");
            return new TokenAdminCommandRunner.IssuePlan(mismatch?"other":c.schema(),
                    UUID.fromString("10000000-0000-0000-0000-000000000001"),UUID.fromString("10000000-0000-0000-0000-000000000002"),
                    c.input(),List.of("customer-one"),t,t.plusSeconds(7200),"FUSE-SECURITY-1",7200,
                    TokenStorageShape.Status.ACTIVE,null,7);
        }
        public void requireCurrent(TokenAdminArguments.Issue c,TokenAdminCommandRunner.IssuePlan p){
            events.add("current"+(++checks));if(fail.equals("current"+checks))throw new TokenAdminCommandRunner.AdmissionRefused();
        }
        public int fillExactly32(byte[] raw){events.add("entropy");rawAlias=raw;Arrays.fill(raw,(byte)0x5a);
            if(fail.equals("entropy"))throw new IllegalStateException(CANARY);return fill;}
        public JdbcTokenIssuanceWriter.InsertResult insertExact(TokenAdminCommandRunner.IssuePlan p,byte[] fingerprint){
            events.add("insert");fingerprintAlias=fingerprint;assertEquals(32,fingerprint.length);
            assertEquals(7,p.revision());assertEquals("FUSE-SECURITY-1",p.securityPolicy());assertEquals(7200,p.issuanceTtlSeconds());
            if(fail.equals("insert"))throw new IllegalStateException(CANARY);
            return new JdbcTokenIssuanceWriter.InsertResult(stored,dbCleanup);
        }
        public TokenIssuanceOutcomeProjector.Delivery deliverOneBounded(byte[] wire){
            events.add("delivery");wireAlias=wire;delivered=new String(wire,StandardCharsets.US_ASCII);
            assertEquals(43,wire.length);assertFalse(delivered.contains("\n"));assertFalse(delivered.contains("\r"));
            if(fail.equals("delivery"))throw new IllegalStateException(CANARY);return delivery;
        }
        public TokenAdminCommandRunner.ChannelCleanup closeChannels(){events.add("close");
            if(fail.equals("close"))throw new IllegalStateException(CANARY);return cleanup;}
    }
    private static TokenAdminCommandRunner.CommandOutcome run(Session s){
        return TokenAdminCommandRunner.execute(issue(),c->{s.events.add("bind");return s;});
    }
    private static void safe(TokenAdminCommandRunner.CommandOutcome o){
        assertFalse(o.metadataJson().contains(CANARY));assertFalse(o.toString().contains(CANARY));
        assertFalse(o.automaticRetryAllowed());assertFalse(o.reissueAllowed());assertFalse(o.executionAuthorityGranted());
        assertEquals(TokenIssuanceOutcomeProjector.CurrentRowState.UNKNOWN,o.issuance().currentRowState());
    }
    private static void zero(byte[] value){assertNotNull(value);for(byte b:value)assertEquals(0,b);}
    @Test void malformedArgumentsNeverCallBackend(){
        var o=TokenAdminCommandRunner.execute(new String[]{"issue","--schema",CANARY},c->{fail("backend");return null;});
        assertEquals(2,o.exitCode());assertEquals(TokenAdminCommandRunner.CommandStatus.INPUT_REJECTED,o.status());safe(o);
    }
    @Test void absentOrUnconfiguredSessionHasNoEntropyStorageOrDelivery(){
        assertEquals(3,TokenAdminCommandRunner.execute(issue(),null).exitCode());
        int[] bind={0};var o=TokenAdminCommandRunner.execute(issue(),c->{bind[0]++;return null;});
        assertEquals(1,bind[0]);assertEquals(3,o.exitCode());assertEquals(TokenAdminCommandRunner.ChannelCleanup.NOT_APPLICABLE,o.channelCleanup());safe(o);
    }
    @Test void validUnsupportedCommandsRemainUnconfiguredWithoutBackend(){
        for(String[] args:List.of(new String[]{"init","--schema","synthetic","--credential-input-fd","0","--registry-id","10000000-0000-0000-0000-000000000002"},
                new String[]{"list","--schema","synthetic","--credential-input-fd","3","--actor","synthetic-admin-target"},
                new String[]{"revoke","--schema","synthetic","--credential-input-fd","3","--selection-id","10000000-0000-0000-0000-000000000001","--expected-revision","7"}))
            assertEquals(3,TokenAdminCommandRunner.execute(args,c->{fail("unsupported backend");return null;}).exitCode());
    }
    @Test void confirmedInsertPrecedesOneExactDeliveryAndAllBuffersAreCleared(){
        var s=new Session();var o=run(s);assertEquals(0,o.exitCode());
        assertEquals(List.of("bind","plan","current1","entropy","current2","insert","delivery","close"),s.events);
        assertEquals(TokenIssuanceOutcomeProjector.Status.INSERT_AND_DELIVERY_CONFIRMED,o.issuance().status());
        assertFalse(o.metadataJson().contains(s.delivered));zero(s.rawAlias);zero(s.fingerprintAlias);zero(s.wireAlias);safe(o);
    }
    @Test void explicitPlanMismatchRefusesBeforeEntropy(){
        var s=new Session();s.mismatch=true;var o=run(s);assertEquals(2,o.exitCode());
        assertEquals(List.of("bind","plan","close"),s.events);safe(o);
    }
    @Test void currentAdmissionRefusalAndSecondFenceStopBeforeInsert(){
        for(String stage:List.of("plan","current1","current2")){
            var s=new Session();s.fail=stage;var o=run(s);assertEquals(2,o.exitCode());
            assertFalse(s.events.contains("insert"));assertFalse(s.events.contains("delivery"));assertEquals("close",s.events.get(s.events.size()-1));safe(o);
        }
    }
    @Test void shortOrThrowingEntropyNeverWritesAndClearsRaw(){
        for(boolean throwsError:List.of(false,true)){
            var s=new Session();s.fill=31;if(throwsError)s.fail="entropy";var o=run(s);
            assertEquals(4,o.exitCode());assertFalse(s.events.contains("insert"));assertFalse(s.events.contains("delivery"));zero(s.rawAlias);safe(o);
        }
    }
    @Test void unconfirmedCommitNeverDeliversOrRetries(){
        var s=new Session();s.stored=JdbcTokenIssuanceWriter.Outcome.COMMIT_UNCONFIRMED;var o=run(s);
        assertEquals(4,o.exitCode());assertEquals(TokenIssuanceOutcomeProjector.StorageEvidence.COMMIT_UNCONFIRMED,o.issuance().storage());
        assertEquals(TokenIssuanceOutcomeProjector.Delivery.NOT_ATTEMPTED,o.issuance().delivery());assertFalse(s.events.contains("delivery"));
        assertEquals(1,Collections.frequency(s.events,"insert"));safe(o);
    }
    @Test void unclassifiedWriterExceptionDoesNotBecomeRollbackProof(){
        var s=new Session();s.fail="insert";var o=run(s);assertEquals(4,o.exitCode());
        assertEquals(TokenIssuanceOutcomeProjector.Status.STORAGE_RESULT_UNKNOWN,o.issuance().status());assertFalse(s.events.contains("delivery"));safe(o);
    }
    @Test void failedUnknownNullOrThrowingSinkHasNoSecondCall(){
        for(String mode:List.of("FAILED","UNKNOWN","NULL","THROW")){
            var s=new Session();s.delivery=mode.equals("FAILED")?TokenIssuanceOutcomeProjector.Delivery.FAILED:
                    mode.equals("UNKNOWN")?TokenIssuanceOutcomeProjector.Delivery.UNKNOWN:null;
            if(mode.equals("THROW"))s.fail="delivery";var o=run(s);assertEquals(4,o.exitCode());
            assertEquals(TokenIssuanceOutcomeProjector.StorageEvidence.INSERT_CONFIRMED,o.issuance().storage());
            assertEquals(TokenIssuanceOutcomeProjector.Status.DELIVERY_UNCONFIRMED,o.issuance().status());
            assertEquals(1,Collections.frequency(s.events,"delivery"));zero(s.wireAlias);safe(o);
        }
    }
    @Test void databaseCleanupUnknownDoesNotEraseAcknowledgedCommitAndDelivery(){
        var s=new Session();s.dbCleanup=JdbcTokenIssuanceWriter.Cleanup.UNCONFIRMED;var o=run(s);assertEquals(4,o.exitCode());
        assertEquals(TokenIssuanceOutcomeProjector.Status.INSERT_AND_DELIVERY_CONFIRMED,o.issuance().status());
        assertEquals(TokenIssuanceOutcomeProjector.Cleanup.UNKNOWN,o.issuance().cleanup());safe(o);
    }
    @Test void channelCleanupUnknownOrThrowPreservesIndependentDatabaseEvidence(){
        for(boolean throwsError:List.of(false,true)){
            var s=new Session();s.cleanup=TokenAdminCommandRunner.ChannelCleanup.UNKNOWN;if(throwsError)s.fail="close";
            var o=run(s);assertEquals(4,o.exitCode());assertEquals(TokenIssuanceOutcomeProjector.Status.INSERT_AND_DELIVERY_CONFIRMED,o.issuance().status());
            assertEquals(TokenIssuanceOutcomeProjector.Cleanup.CONFIRMED,o.issuance().cleanup());
            assertEquals(TokenAdminCommandRunner.ChannelCleanup.UNKNOWN,o.channelCleanup());assertEquals(1,Collections.frequency(s.events,"close"));safe(o);
        }
    }
    @Test void bindingExceptionIsUncertainNotAFalseNoEffectUnconfigured(){
        var o=TokenAdminCommandRunner.execute(issue(),c->{throw new IllegalStateException(CANARY);});
        assertEquals(4,o.exitCode());assertEquals(TokenAdminCommandRunner.ChannelCleanup.UNKNOWN,o.channelCleanup());safe(o);
    }
    @Test void refusedBeforeWriteWithChannelUncertaintyDoesNotContradictNoWriteProjector(){
        var s=new Session();s.fail="plan";s.cleanup=TokenAdminCommandRunner.ChannelCleanup.UNKNOWN;
        var o=run(s);assertEquals(4,o.exitCode());assertEquals(TokenAdminCommandRunner.CommandStatus.REFUSED,o.status());
        assertEquals(TokenIssuanceOutcomeProjector.StorageEvidence.NOT_ATTEMPTED,o.issuance().storage());
        assertEquals(TokenIssuanceOutcomeProjector.Cleanup.NOT_APPLICABLE,o.issuance().cleanup());
        assertEquals(TokenAdminCommandRunner.ChannelCleanup.UNKNOWN,o.channelCleanup());assertFalse(s.events.contains("entropy"));safe(o);
    }
    @Test void actualEntrypointUsesAbsentBackendAndEmitsOnlyFiniteMetadata(){
        var bytes=new ByteArrayOutputStream();int exit=DemoTokenProvisioner.run(issue(),new PrintStream(bytes, true,StandardCharsets.US_ASCII));
        assertEquals(3,exit);String text=bytes.toString(StandardCharsets.US_ASCII);
        assertTrue(text.contains("\"status\":\"UNCONFIGURED\""));assertTrue(text.endsWith("}\n"));assertTrue(text.length()<1024);
        assertFalse(text.contains("synthetic-admin-target"));assertFalse(text.contains("customer-one"));
    }
    @Test void metadataSinkFailureReturnsUnknownWithoutReexecutingBackend(){
        var sink=new PrintStream(new OutputStream(){@Override public void write(int value)throws IOException{throw new IOException(CANARY);}});
        assertEquals(4,DemoTokenProvisioner.run(issue(),sink));
    }
}
