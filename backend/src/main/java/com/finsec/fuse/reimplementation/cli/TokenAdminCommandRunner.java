package com.finsec.fuse.reimplementation.cli;

import com.finsec.fuse.reimplementation.auth.TokenMaterialCodec;
import com.finsec.fuse.reimplementation.auth.TokenRegistryInput;
import com.finsec.fuse.reimplementation.auth.TokenStorageShape;
import com.finsec.fuse.reimplementation.auth.TokenIssuanceOutcomeProjector;
import com.finsec.fuse.reimplementation.persistence.JdbcTokenIssuanceWriter;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Issue-only orchestration through explicitly trusted native/admin adapters; no ambient backend. */
public final class TokenAdminCommandRunner {
    private TokenAdminCommandRunner() { }
    public enum CommandStatus { INPUT_REJECTED, UNCONFIGURED, REFUSED, CONFIRMED, UNKNOWN }
    public enum ChannelCleanup { NOT_APPLICABLE, CONFIRMED, UNKNOWN }
    /** Trusted deployment port, not a credential or caller assertion. No production implementation is installed. */
    @FunctionalInterface public interface PreparedAdminBackend {
        NativeAdminSession bind(TokenAdminArguments.Issue requested);
    }
    /** Must own actual protected descriptors/admin admission for the exact parsed operation and target.
     * Synthetic implementations exercise sequencing only; implementing this interface proves no native facts.
     * Null bind means effect-free UNCONFIGURED. Exceptions during binding leave cleanup UNKNOWN.
     */
    public interface NativeAdminSession {
        IssuePlan prepareIssue(TokenAdminArguments.Issue requested);
        void requireCurrent(TokenAdminArguments.Issue requested, IssuePlan plan);
        int fillExactly32(byte[] ownedBuffer);
        JdbcTokenIssuanceWriter.InsertResult insertExact(IssuePlan plan, byte[] fingerprint);
        TokenIssuanceOutcomeProjector.Delivery deliverOneBounded(byte[] canonical43Ascii);
        ChannelCleanup closeChannels();
    }
    /** Explicit existing JDBC row metadata; no default identifiers, status, revision or time. */
    public record IssuePlan(String schema, UUID selectionId, UUID registryId, TokenRegistryInput initial,
            List<String> currentScope, Instant issuedAt, Instant expiresAt, String securityPolicy,
            int issuanceTtlSeconds, TokenStorageShape.Status status, Instant revokedAt, long revision) {
        public IssuePlan {
            if(schema==null||!schema.matches("[A-Za-z_][A-Za-z0-9_]{0,62}")||selectionId==null||initial==null)
                throw new IllegalArgumentException("INVALID_ISSUE_PLAN",null);
            currentScope=List.copyOf(Objects.requireNonNull(currentScope));
            new TokenRegistryInput(initial.actorId(),initial.role(),currentScope);
            TokenStorageShape.validate(new byte[32],registryId,securityPolicy,issuanceTtlSeconds,
                    issuedAt,expiresAt,status,revokedAt,revision);
        }
        @Override public String toString(){return "IssuePlan[REDACTED]";}
    }
    public static final class AdmissionRefused extends RuntimeException {
        public AdmissionRefused(){super("ADMIN_ADMISSION_REFUSED",null,false,false);}
    }
    /** Existing JDBC implementation bridge. Construction opens no connection; caller binds schema/session. */
    public static JdbcTokenIssuanceWriter.InsertResult insertWithJdbc(JdbcTokenIssuanceWriter writer,
            IssuePlan plan,byte[] fingerprint) {
        Objects.requireNonNull(writer);Objects.requireNonNull(plan);
        return writer.insertExact(plan.selectionId(),plan.registryId(),fingerprint,plan.initial(),plan.currentScope(),
                plan.issuedAt(),plan.expiresAt(),plan.securityPolicy(),plan.issuanceTtlSeconds(),plan.status(),
                plan.revokedAt(),plan.revision());
    }
    public static final class CommandOutcome {
        private final CommandStatus status;
        private final TokenIssuanceOutcomeProjector.Projection issuance;
        private final ChannelCleanup channelCleanup;
        private CommandOutcome(CommandStatus status,TokenIssuanceOutcomeProjector.Projection issuance,
                ChannelCleanup channelCleanup){this.status=status;this.issuance=issuance;this.channelCleanup=channelCleanup;}
        public CommandStatus status(){return status;}
        public TokenIssuanceOutcomeProjector.Projection issuance(){return issuance;}
        public ChannelCleanup channelCleanup(){return channelCleanup;}
        public boolean automaticRetryAllowed(){return false;}
        public boolean reissueAllowed(){return false;}
        public boolean executionAuthorityGranted(){return false;}
        public int exitCode(){
            if(channelCleanup==ChannelCleanup.UNKNOWN||status==CommandStatus.UNKNOWN)return 4;
            return switch(status){case CONFIRMED->0;case INPUT_REJECTED,REFUSED->2;case UNCONFIGURED->3;case UNKNOWN->4;};
        }
        public String metadataJson(){
            return "{\"status\":\""+status.name()+"\",\"storage\":\""+issuance.storage().name()
                    +"\",\"delivery\":\""+issuance.delivery().name()+"\",\"databaseCleanup\":\""+issuance.cleanup().name()
                    +"\",\"channelCleanup\":\""+channelCleanup.name()+"\",\"currentRowState\":\"UNKNOWN\","
                    +"\"automaticRetryAllowed\":false,\"reissueAllowed\":false,\"executionAuthorityGranted\":false}\n";
        }
        @Override public String toString(){return "TokenAdminCommandOutcome["+status.name()+"]";}
    }
    private static CommandOutcome noWrite(CommandStatus status,ChannelCleanup cleanup){
        return new CommandOutcome(status,TokenIssuanceOutcomeProjector.project(new TokenIssuanceOutcomeProjector.Input(
                TokenIssuanceOutcomeProjector.StorageEvidence.NOT_ATTEMPTED,
                TokenIssuanceOutcomeProjector.Delivery.NOT_ATTEMPTED,TokenIssuanceOutcomeProjector.Cleanup.NOT_APPLICABLE)),cleanup);
    }
    /** No default provider, FD acquisition, registry population or LocalAuth enrollment. */
    public static CommandOutcome execute(String[] arguments,PreparedAdminBackend backend){
        TokenAdminArguments.Command parsed;
        try{
            if(arguments!=null&&arguments.length>0&&"revoke".equals(arguments[0])){
                TokenRevocationArguments.parse(arguments);
                return noWrite(CommandStatus.UNCONFIGURED,ChannelCleanup.NOT_APPLICABLE);
            }
            parsed=TokenAdminArguments.parse(arguments);
        }catch(RuntimeException invalid){return noWrite(CommandStatus.INPUT_REJECTED,ChannelCleanup.NOT_APPLICABLE);}
        if(!(parsed instanceof TokenAdminArguments.Issue requested)||backend==null)
            return noWrite(CommandStatus.UNCONFIGURED,ChannelCleanup.NOT_APPLICABLE);
        NativeAdminSession session=null;
        ChannelCleanup channels=ChannelCleanup.NOT_APPLICABLE;
        CommandStatus status=CommandStatus.UNKNOWN;
        var storage=TokenIssuanceOutcomeProjector.StorageEvidence.NOT_ATTEMPTED;
        var delivery=TokenIssuanceOutcomeProjector.Delivery.NOT_ATTEMPTED;
        var dbCleanup=TokenIssuanceOutcomeProjector.Cleanup.NOT_APPLICABLE;
        byte[] raw=null,fingerprint=null,wire=null;
        boolean insertAttempted=false;
        try{
            channels=ChannelCleanup.UNKNOWN;
            session=backend.bind(requested);
            if(session==null)return noWrite(CommandStatus.UNCONFIGURED,ChannelCleanup.NOT_APPLICABLE);
            var plan=session.prepareIssue(requested);
            if(plan==null||!plan.schema().equals(requested.schema())||!plan.initial().equals(requested.input()))
                throw new AdmissionRefused();
            session.requireCurrent(requested,plan);
            raw=new byte[32];
            if(session.fillExactly32(raw)!=32)throw new IllegalStateException();
            var material=TokenMaterialCodec.encode(raw);
            fingerprint=material.fingerprint();
            wire=material.bearer().getBytes(StandardCharsets.US_ASCII);
            if(wire.length!=43)throw new IllegalStateException();
            session.requireCurrent(requested,plan);
            insertAttempted=true;
            storage=TokenIssuanceOutcomeProjector.StorageEvidence.STORAGE_FAILURE_UNCLASSIFIED;
            dbCleanup=TokenIssuanceOutcomeProjector.Cleanup.UNKNOWN;
            var written=session.insertExact(plan,fingerprint);
            if(written==null)throw new IllegalStateException();
            dbCleanup=written.cleanup()==JdbcTokenIssuanceWriter.Cleanup.CONFIRMED
                    ?TokenIssuanceOutcomeProjector.Cleanup.CONFIRMED:TokenIssuanceOutcomeProjector.Cleanup.UNKNOWN;
            if(written.outcome()==JdbcTokenIssuanceWriter.Outcome.COMMIT_UNCONFIRMED){
                storage=TokenIssuanceOutcomeProjector.StorageEvidence.COMMIT_UNCONFIRMED;
            }else{
                storage=TokenIssuanceOutcomeProjector.StorageEvidence.INSERT_CONFIRMED;
                delivery=TokenIssuanceOutcomeProjector.Delivery.UNKNOWN;
                var observed=session.deliverOneBounded(wire);
                if(observed==TokenIssuanceOutcomeProjector.Delivery.COMPLETE||observed==TokenIssuanceOutcomeProjector.Delivery.FAILED
                        ||observed==TokenIssuanceOutcomeProjector.Delivery.UNKNOWN)delivery=observed;
                if(delivery==TokenIssuanceOutcomeProjector.Delivery.COMPLETE&&dbCleanup==TokenIssuanceOutcomeProjector.Cleanup.CONFIRMED)
                    status=CommandStatus.CONFIRMED;
            }
        }catch(AdmissionRefused refused){status=insertAttempted?CommandStatus.UNKNOWN:CommandStatus.REFUSED;}
        catch(RuntimeException unknown){status=CommandStatus.UNKNOWN;}
        finally{
            if(raw!=null)Arrays.fill(raw,(byte)0);
            if(fingerprint!=null)Arrays.fill(fingerprint,(byte)0);
            if(wire!=null)Arrays.fill(wire,(byte)0);
            if(session!=null){
                try{channels=session.closeChannels();if(channels!=ChannelCleanup.CONFIRMED)channels=ChannelCleanup.UNKNOWN;}
                catch(RuntimeException unknown){channels=ChannelCleanup.UNKNOWN;}
            }
        }
        return new CommandOutcome(status,TokenIssuanceOutcomeProjector.project(
                new TokenIssuanceOutcomeProjector.Input(storage,delivery,dbCleanup)),channels);
    }
    /** Fixed secret-free fallback for entrypoint fatal/metadata emission failures; no retry. */
    public static CommandOutcome unknown(){return noWrite(CommandStatus.UNKNOWN,ChannelCleanup.UNKNOWN);}
}
