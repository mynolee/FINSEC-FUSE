package com.finsec.fuse.workflow;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.SecurityPolicy;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** The model returns a proposal, never an authorization. Binding is copied by the Python server. */
public final class KycContract {
    private KycContract() {}

    public record EvidenceFact(UUID evidenceId, String kind, String result) {}
    public record Document(UUID documentId, int documentVersion, String contentHash, String text) {}
    public record Input(UUID requestId, UUID workflowId, int generation, UUID runId, String customerId,
                        String policyVersion, String inputSnapshotHash, List<EvidenceFact> evidenceFacts,
                        List<Document> documents) {
        public Input { evidenceFacts=List.copyOf(evidenceFacts); documents=List.copyOf(documents); }
        public void validate(Json json, SecurityPolicy policy) {
            if(requestId==null || workflowId==null || generation<1 || runId==null ||
               customerId==null || customerId.isEmpty() || customerId.codePointCount(0,customerId.length())>64 ||
               policyVersion==null || policyVersion.isEmpty() || policyVersion.codePointCount(0,policyVersion.length())>64 ||
               inputSnapshotHash==null || !inputSnapshotHash.matches("[0-9a-f]{64}") ||
               evidenceFacts.size()>policy.evidenceFactsMaxItems() || documents.size()>policy.documentsMaxItems())
                throw new IllegalArgumentException("Invalid KYC input");
            for(var fact:evidenceFacts)if(fact.evidenceId()==null || !Set.of("ID_DOC","FACE_MATCH").contains(fact.kind()) ||
                !Set.of("PASS","FAIL").contains(fact.result()))throw new IllegalArgumentException("Invalid evidence fact");
            for(var document:documents) {
                if(document.documentId()==null || document.documentVersion()<1 || document.text()==null ||
                    document.text().getBytes(StandardCharsets.UTF_8).length>policy.documentTextMaxUtf8Bytes() ||
                    !Json.sha256(document.text().getBytes(StandardCharsets.UTF_8)).equals(document.contentHash()))
                    throw new IllegalArgumentException("Invalid KYC document");
            }
            if(!json.hash(unhashed()).equals(inputSnapshotHash))throw new IllegalArgumentException("Invalid KYC input snapshot");
        }
        /** This exact insertion order is shared with Python and excludes the digest itself. */
        public Map<String,Object> unhashed() {
            return Json.ordered("requestId", requestId, "workflowId", workflowId, "generation", generation,
                    "runId", runId, "customerId", customerId, "policyVersion", policyVersion,
                    "evidenceFacts", evidenceFacts, "documents", documents);
        }
        public Input withHash(String hash) {
            return new Input(requestId, workflowId, generation, runId, customerId, policyVersion,
                    hash, evidenceFacts, documents);
        }
    }
    public enum ProposalStatus { VERIFIED, NOT_VERIFIED, NEEDS_REVIEW }
    public record Proposal(ProposalStatus status, List<UUID> evidenceIds, String explanation) {
        public Proposal {
            if (status == null || evidenceIds == null || evidenceIds.size() > 10 ||
                    evidenceIds.stream().anyMatch(Objects::isNull) || explanation == null || explanation.isEmpty() || explanation.codePointCount(0,explanation.length()) > 2000)
                throw new IllegalArgumentException("Invalid KYC proposal");
            evidenceIds = List.copyOf(evidenceIds);
        }
    }
    public record ModelMetadata(String model, String promptVersion) {
        public ModelMetadata {
            if (model == null || model.isBlank() || model.codePointCount(0,model.length()) > 160 || !"KYC-PROMPT-1".equals(promptVersion))
                throw new IllegalArgumentException("Invalid model metadata");
        }
    }
    public record Response(UUID requestId, UUID workflowId, int generation, UUID runId,
                           String inputSnapshotHash, Proposal proposal, ModelMetadata modelMetadata) {
        public Response {
            if (requestId == null || workflowId == null || generation < 1 || runId == null ||
                    inputSnapshotHash == null || !inputSnapshotHash.matches("[0-9a-f]{64}") ||
                    proposal == null || modelMetadata == null)
                throw new IllegalArgumentException("Invalid KYC response");
        }
        public boolean boundTo(Input input) {
            return requestId.equals(input.requestId()) && workflowId.equals(input.workflowId()) &&
                    generation == input.generation() && runId.equals(input.runId()) &&
                    inputSnapshotHash.equals(input.inputSnapshotHash());
        }
    }
    public record Prepared(UUID jobId, UUID leaseToken, Input input) {}
}
