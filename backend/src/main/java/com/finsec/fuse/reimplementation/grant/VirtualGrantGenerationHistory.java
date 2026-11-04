package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec.RiskTerms;
import com.finsec.fuse.reimplementation.simulation.VirtualWorkflowLane.Scope;
import java.time.Instant;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.LinkedHashMap;
import java.util.UUID;

/** Immutable generation provenance and current-head fencing in one caller-owned transaction. */
public final class VirtualGrantGenerationHistory {
    private VirtualGrantGenerationHistory() { }
    public record ExpectedHead(Scope scope, UUID rootGrantId, long revision) {
        public ExpectedHead { if (scope == null || rootGrantId == null || revision < 0) throw invalid(); }
        @Override public String toString() { return "ExpectedHead[REDACTED]"; }
    }
    public record GenerationRecord(Scope scope, UUID rootGrantId, UUID rootRequestId,
            UUID rootTargetRunId, UUID sourceDocId, int sourceVersion, RiskTerms terms, Instant observedAt) {
        public GenerationRecord {
            if (scope == null || rootGrantId == null || rootRequestId == null || rootTargetRunId == null
                    || sourceDocId == null || sourceVersion < 1 || terms == null) throw invalid();
        }
        @Override public String toString() { return "GenerationRecord[REDACTED]"; }
    }
    /** Null observedAt denotes a read-only original-generation projection, never a stored observation. */
    public static GenerationRecord validate(TransactionalStore.Tx tx, Scope scope) {
        if (tx == null || scope == null) throw invalid();
        var requested = readOwn(tx,scope);
        for (int generation=scope.generation()-1; generation>=1; generation--) {
            var prior=readOwn(tx,new Scope(scope.workflowId(),generation,scope.customerId()));
            if (!requested.terms().equals(prior.terms())) throw invalid();
        }
        return requested;
    }
    private static GenerationRecord readOwn(TransactionalStore.Tx tx, Scope scope) {
        var row = tx.get(GENERATIONS,key(scope));
        if (row == null) {
            if (scope.generation() != 1) throw invalid();
            var o = VirtualGrantTransactionJournal.originalGeneration(tx,scope);
            return new GenerationRecord(o.scope(),o.rootGrantId(),o.rootReceiptRequestId(),o.targetRunId(),
                    o.documentId(),o.documentVersion(),o.terms(),null);
        }
        var r = decode(row);
        if (!r.scope().equals(scope)) throw invalid();
        requireOrigin(tx,r);
        return r;
    }
    public static GenerationRecord requireCurrent(TransactionalStore.Tx tx, Scope scope) {
        checkCurrentScope(tx,scope);
        return validate(tx,scope);
    }
    /** A writer fence only; absent head is tolerated solely for existing generation-one initialization. */
    public static void checkCurrentScope(TransactionalStore.Tx tx, Scope scope) {
        if (tx == null || scope == null) throw invalid();
        var workflow=tx.get("virtual_workflows",scope.workflowId().toString());
        var lane=tx.get("virtual_workflow_lanes",scope.workflowId().toString());
        if (workflow == null || lane == null || !"TYPED".equals(lane.get("lane"))) throw invalid();
        for (var row : java.util.List.of(workflow,lane)) {
            if (!scope.workflowId().toString().equals(row.get("workflowId"))
                    || !Integer.valueOf(scope.generation()).equals(row.get("generation"))
                    || !scope.customerId().equals(row.get("customerId"))) throw invalid();
        }
        var row=tx.get(HEADS,scope.workflowId().toString());
        if (row == null) { if (scope.generation()!=1) throw invalid(); return; }
        var head=decodeHead(row);
        if (!head.scope().equals(scope)) throw invalid();
        var generation=validate(tx,scope);
        if (!head.rootGrantId().equals(generation.rootGrantId())) throw invalid();
    }
    public static ExpectedHead readHead(TransactionalStore.Tx tx, UUID workflowId) {
        if (tx == null || workflowId == null) throw invalid();
        var row=tx.get(HEADS,workflowId.toString());
        if (row == null) return null;
        var head=decodeHead(row);
        if (!head.scope().workflowId().equals(workflowId)) throw invalid();
        return head;
    }
    /** Establishes a new observation only from a positively joined original root, never by row absence alone. */
    public static ExpectedHead establishOriginal(TransactionalStore.Tx tx, GenerationRecord observed, long revision) {
        if (tx == null || observed == null || observed.scope().generation()!=1 || observed.observedAt()==null || revision<0) throw invalid();
        checkCurrentScope(tx,observed.scope());
        if (readHead(tx,observed.scope().workflowId())!=null || tx.get(GENERATIONS,key(observed.scope()))!=null) throw invalid();
        requireOrigin(tx,observed);
        var expected=new ExpectedHead(observed.scope(),observed.rootGrantId(),revision);
        tx.put(GENERATIONS,key(observed.scope()),recordRow(observed));
        tx.put(HEADS,observed.scope().workflowId().toString(),headRow(expected));
        return expected;
    }
    /** Caller publishes workflow/lane/root/receipt changes in this same transaction or rolls the entire work back. */
    public static ExpectedHead advance(TransactionalStore.Tx tx, ExpectedHead expected, GenerationRecord next) {
        if (tx == null || expected == null || next == null || next.observedAt()==null) throw invalid();
        checkCurrentScope(tx,expected.scope());
        if (!expected.equals(readHead(tx,expected.scope().workflowId()))) throw invalid();
        var previous=validate(tx,expected.scope());
        final int generation; final long revision;
        try { generation=Math.addExact(expected.scope().generation(),1); revision=Math.addExact(expected.revision(),1L); }
        catch (ArithmeticException overflow) { throw invalid(); }
        if (!next.scope().workflowId().equals(expected.scope().workflowId()) || next.scope().generation()!=generation
                || !next.scope().customerId().equals(expected.scope().customerId()) || !next.terms().equals(previous.terms())
                || next.rootGrantId().equals(previous.rootGrantId()) || next.rootRequestId().equals(previous.rootRequestId())
                || next.rootTargetRunId().equals(previous.rootTargetRunId()) || tx.get(GENERATIONS,key(next.scope()))!=null) throw invalid();
        requireOrigin(tx,next);
        var head=new ExpectedHead(next.scope(),next.rootGrantId(),revision);
        tx.put(GENERATIONS,key(next.scope()),recordRow(next));
        tx.put(HEADS,next.scope().workflowId().toString(),headRow(head));
        return head;
    }
    private static void requireOrigin(TransactionalStore.Tx tx, GenerationRecord r) {
        var o=VirtualGrantTransactionJournal.generationOrigin(tx,r.scope(),r.rootGrantId(),r.rootRequestId());
        if (!o.scope().equals(r.scope()) || !o.rootGrantId().equals(r.rootGrantId())
                || !o.rootReceiptRequestId().equals(r.rootRequestId()) || !o.targetRunId().equals(r.rootTargetRunId())
                || !o.documentId().equals(r.sourceDocId()) || o.documentVersion()!=r.sourceVersion()
                || !o.terms().equals(r.terms())) throw invalid();
    }
    private static final String GENERATIONS = "virtual_grant_profile_generations";
    private static final String HEADS = "virtual_grant_profile_current_heads";
    private static final Set<String> RECORD_KEYS = Set.of("workflowId", "generation", "customerId", "rootGrantId",
            "rootRequestId", "rootTargetRunId", "sourceDocId", "sourceVersion", "terms", "observedAt");
    private static final Set<String> HEAD_KEYS = Set.of("workflowId", "generation", "customerId", "rootGrantId", "revision");
    private static String key(Scope scope) { return scope.workflowId() + ":" + scope.generation(); }
    private static Map<String,Object> recordRow(GenerationRecord r) {
        var m = new LinkedHashMap<String,Object>();
        m.put("workflowId", r.scope().workflowId().toString()); m.put("generation", r.scope().generation());
        m.put("customerId", r.scope().customerId()); m.put("rootGrantId", r.rootGrantId().toString());
        m.put("rootRequestId", r.rootRequestId().toString()); m.put("rootTargetRunId", r.rootTargetRunId().toString());
        m.put("sourceDocId", r.sourceDocId().toString()); m.put("sourceVersion", r.sourceVersion());
        m.put("terms", termsRow(r.terms())); m.put("observedAt", r.observedAt().toString()); return Map.copyOf(m);
    }
    private static Map<String,Object> termsRow(RiskTerms t) {
        return Map.of("policyVersion",t.policyVersion(),"kycPoints",t.kycPoints(),"loanPoints",t.loanPoints(),
                "payPoints",t.payPoints(),"baseLimit",t.baseLimit(),"additionalApprovalLimit",t.additionalApprovalLimit(),
                "maxAutomaticKycRuns",t.maxAutomaticKycRuns(),"approvalLifetime",t.approvalLifetime().toString());
    }
    private static GenerationRecord decode(Map<String,Object> m) {
        try {
            if (m == null || !m.keySet().equals(RECORD_KEYS) || m.get("observedAt")==null) throw invalid();
            var r = new GenerationRecord(new Scope(uuid(m,"workflowId"),number(m,"generation"),text(m,"customerId")),
                    uuid(m,"rootGrantId"),uuid(m,"rootRequestId"),uuid(m,"rootTargetRunId"),uuid(m,"sourceDocId"),
                    number(m,"sourceVersion"),decodeTerms(m.get("terms")),Instant.parse(text(m,"observedAt")));
            if (!recordRow(r).equals(m)) throw invalid(); return r;
        } catch (RuntimeException rejected) { throw invalid(); }
    }
    private static RiskTerms decodeTerms(Object value) {
        if (!(value instanceof Map<?,?> raw) || !raw.keySet().equals(Set.of("policyVersion","kycPoints","loanPoints",
                "payPoints","baseLimit","additionalApprovalLimit","maxAutomaticKycRuns","approvalLifetime"))) throw invalid();
        var m = new LinkedHashMap<String,Object>();
        for (var e : raw.entrySet()) { if (!(e.getKey() instanceof String k)) throw invalid(); m.put(k,e.getValue()); }
        return new RiskTerms(text(m,"policyVersion"),number(m,"kycPoints"),number(m,"loanPoints"),number(m,"payPoints"),
                number(m,"baseLimit"),number(m,"additionalApprovalLimit"),number(m,"maxAutomaticKycRuns"),
                Duration.parse(text(m,"approvalLifetime")));
    }
    private static Map<String,Object> headRow(ExpectedHead h) {
        return Map.of("workflowId",h.scope().workflowId().toString(),"generation",h.scope().generation(),
                "customerId",h.scope().customerId(),"rootGrantId",h.rootGrantId().toString(),"revision",h.revision());
    }
    private static ExpectedHead decodeHead(Map<String,Object> m) {
        try {
            if (m == null || !m.keySet().equals(HEAD_KEYS) || !(m.get("revision") instanceof Long revision)) throw invalid();
            return new ExpectedHead(new Scope(uuid(m,"workflowId"),number(m,"generation"),text(m,"customerId")),uuid(m,"rootGrantId"),revision);
        } catch (RuntimeException rejected) { throw invalid(); }
    }
    private static UUID uuid(Map<String,Object> m,String k) {
        String v=text(m,k); UUID id=UUID.fromString(v); if (!id.toString().equals(v)) throw invalid(); return id;
    }
    private static String text(Map<String,Object> m,String k) {
        if (!(m.get(k) instanceof String v) || v.isBlank()) throw invalid(); return v;
    }
    private static int number(Map<String,Object> m,String k) {
        if (!(m.get(k) instanceof Integer v)) throw invalid(); return v;
    }
    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("INVALID_GENERATION_HISTORY", null);
    }
}
