package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.MockLoanRule;
import com.finsec.fuse.reimplementation.grant.TypedWorkflowReadProjection;
import com.finsec.fuse.reimplementation.grant.TypedWorkflowTraceProjection;
import com.finsec.fuse.reimplementation.WorkflowHttpController;
import com.finsec.fuse.reimplementation.WorkflowResumeBoundary;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary.ActorRef;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;
import static com.finsec.fuse.reimplementation.simulation.SimulationRows.*;

/**
 * Independently authored, explicitly VIRTUAL backend. No real database, money,
 * identity checks, model call, cryptographic authority, or production bootstrap.
 * Every mutation and replay receipt share one virtual transaction.
 */
public final class VirtualWorkflowService implements WorkflowHttpController.CommandPort {
    static final String WORKFLOWS = "virtual_workflows", JOBS = "virtual_jobs",
            RUNS = "virtual_runs", RESULTS = "virtual_results", APPROVALS = "virtual_approvals",
            RESERVATIONS = "virtual_reservations", PAYMENTS = "virtual_payments",
            RISK = "virtual_risk_events", AUDIT = "virtual_audit", LINKS = "virtual_dependencies",
            QUARANTINES = "virtual_quarantines";
    public static final String AGENT_ID = "synthetic-kyc";
    public static final int AGENT_VERSION = 1;
    private final TransactionalStore store;
    private final ActionJournal journal;
    private final SimulationSpec.Catalog catalog;
    private final SimulationSpec.RiskTerms terms;
    private final SimulationAccess access;
    private final Clock clock;
    private final Supplier<UUID> ids;
    private final VirtualDeliveryCoordinator.Notifications delivery;
    private final VirtualResultRecording.Port resultRecording = VirtualResultRecording.transactionPort();

    public VirtualWorkflowService(TransactionalStore store, SimulationSpec.Catalog catalog,
            SimulationSpec.RiskTerms terms, SimulationAccess access, Clock clock, Supplier<UUID> ids) {
        this(store, catalog, terms, access, clock, ids, null);
    }
    public VirtualWorkflowService(TransactionalStore store, SimulationSpec.Catalog catalog,
            SimulationSpec.RiskTerms terms, SimulationAccess access, Clock clock, Supplier<UUID> ids,
            VirtualDeliveryCoordinator.Notifications delivery) {
        this.delivery = delivery;
        this.store = Objects.requireNonNull(store); this.catalog = Objects.requireNonNull(catalog);
        this.terms = Objects.requireNonNull(terms); this.access = Objects.requireNonNull(access);
        this.clock = Objects.requireNonNull(clock); this.ids = Objects.requireNonNull(ids);
        if (!VirtualTransactionalStore.MODE.equals(store.mode())) throw new IllegalArgumentException("An explicit virtual store is required");
        this.journal = new ActionJournal(store);
    }

    @Override public WorkflowHttpController.Receipt start(WorkflowStartBoundary.Command command) {
        var app = catalog.application(command.request());
        access.require(command.actor(), SimulationAccess.Operation.START, null, app.customerId());
        var payload = object("businessReference", app.businessReference(), "customerId", app.customerId(),
                "amountKrw", app.amountKrw(), "payoutAccountId", app.payoutAccountId().toString());
        return notifyKyc(wire(journal.execute(command.actor().actorId(), command.requestId(), "SIM_START",
                CanonicalJson.sha256(payload), tx -> {
            // Replay prechecks and mutation admission are distinct authority checks.
            access.require(command.actor(), SimulationAccess.Operation.START, null, app.customerId());
            if (tx.rows(WORKFLOWS).values().stream().anyMatch(w -> app.businessReference().equals(w.get("businessReference"))))
                throw SimulationFailure.invalid();
            UUID id = fresh(tx, WORKFLOWS, ids);
            var workflow = object("workflowId", id.toString(), "generation", 1, "state", "KYC_PENDING",
                    "businessReference", app.businessReference(), "customerId", app.customerId(),
                    "amountKrw", app.amountKrw(), "payoutAccountId", app.payoutAccountId().toString(),
                    "documentId", app.source().documentId().toString(), "documentVersion", app.source().documentVersion(),
                    "usedRisk", 0, "reservedRisk", 0, "riskLimit", terms.baseLimit(), "kycRuns", 0,
                    "currentKycResultId", null, "currentLoanResultId", null, "activeJobId", null,
                    "reasonCodes", List.of(), "lastDecision", "ALLOW", "policyVersion", terms.policyVersion());
            requireLegacyLane(tx, workflow);
            tx.put(WORKFLOWS, id.toString(), workflow);
            if (!app.source().reviewedSafe() || held(tx, workflow)) {
                workflow = transition(tx, workflow, "BLOCKED", "DENY", "SOURCE_OR_SCOPE_BLOCKED");
            } else {
                UUID job = job(tx, workflow, "KYC", null);
                workflow = changed(workflow, "activeJobId", job.toString());
                tx.put(WORKFLOWS, id.toString(), workflow);
            }
            event(tx, id, command.requestId(), "WORKFLOW_CREATED");
            return receipt(command.requestId(), workflow);
        })));
    }

    @Override public WorkflowHttpController.Receipt resume(WorkflowResumeBoundary.Command command) {
        authorizeBeforeReplay(command.actor(), SimulationAccess.Operation.RESUME, command.workflowId());
        return notifyKyc(wire(journal.execute(command.actor().actorId(), command.requestId(), "SIM_RESUME",
                CanonicalJson.sha256(object("workflowId", command.workflowId().toString(),
                        "expectedGeneration", command.request().expectedGeneration(), "reason", command.request().reason())), tx -> {
            var workflow = require(tx, WORKFLOWS, command.workflowId());
            authorize(command.actor(), SimulationAccess.Operation.RESUME, workflow);
            requireLegacyLane(tx, workflow);
            if (integer(workflow, "generation") != command.request().expectedGeneration()) throw SimulationFailure.invalid();
            String state = (String) workflow.get("state");
            if (!(state.equals("BLOCKED") || state.equals("ON_HOLD"))) throw SimulationFailure.invalid();
            if (!resumeScopeClear(tx, workflow) || !source(workflow).reviewedSafe()
                    || integer(workflow, "kycRuns") >= terms.maxAutomaticKycRuns()
                    || workflow.get("activeJobId") != null) {
                return receipt(command.requestId(), block(tx, workflow, command.requestId(), "RESUME_BLOCKED", "ON_HOLD"));
            }
            invalidate(tx, workflow, command.requestId(), "GENERATION_ADVANCED");
            workflow = changed(workflow, "generation", Math.addExact(integer(workflow, "generation"), 1),
                    "state", "KYC_PENDING", "currentKycResultId", null, "currentLoanResultId", null,
                    "activeJobId", null, "lastDecision", "ALLOW", "reasonCodes", List.of(), "riskLimit", terms.baseLimit());
            UUID job = job(tx, workflow, "KYC", null);
            workflow = changed(workflow, "activeJobId", job.toString());
            tx.put(WORKFLOWS, command.workflowId().toString(), workflow);
            event(tx, command.workflowId(), command.requestId(), "GENERATION_ADVANCED");
            return changed(receipt(command.requestId(), workflow), "kycJobId", job.toString());
        })));
    }

    /** Returns {requestId,...,input} or a saved DENY receipt. Never sends the input anywhere. */
    public Map<String, Object> prepareKyc(ActorRef actor, UUID action, UUID workflowId) {
        return prepareKyc(actor, action, workflowId, null, 0);
    }
    /** Expected queued-job binding is checked before history and again in the mutation transaction. */
    public Map<String, Object> prepareKyc(ActorRef actor, UUID action, UUID workflowId, UUID expectedJobId, int expectedGeneration) {
        authorizeBeforeReplay(actor, SimulationAccess.Operation.KYC_OBSERVATION, workflowId);
        var payload = deliveryPayload(workflowId, expectedJobId, expectedGeneration);
        if (expectedJobId != null) store.transaction(tx -> {
            var current = require(tx, WORKFLOWS, workflowId);
            authorize(actor, SimulationAccess.Operation.KYC_OBSERVATION, current);
            requireExpectedJob(tx, current, expectedJobId, expectedGeneration, "KYC"); return null;
        });
        return journal.execute(actor.actorId(), action, "SIM_PREPARE_KYC",
                CanonicalJson.sha256(payload), tx -> {
            var workflow = require(tx, WORKFLOWS, workflowId);
            authorize(actor, SimulationAccess.Operation.KYC_OBSERVATION, workflow);
            requireLegacyLane(tx, workflow);
            requireExpectedJob(tx, workflow, expectedJobId, expectedGeneration, "KYC");
            if (!"KYC_PENDING".equals(workflow.get("state")) || held(tx, workflow)
                    || integer(workflow, "kycRuns") >= terms.maxAutomaticKycRuns()) {
                workflow = block(tx, workflow, action, "KYC_PRECONDITION_FAILED", "ON_HOLD");
                return receipt(action, workflow);
            }
            var job = require(tx, JOBS, id(workflow, "activeJobId"));
            if (!"PENDING".equals(job.get("state"))) throw SimulationFailure.invalid();
            var source = source(workflow);
            var facts = catalog.factsFor((String) workflow.get("customerId"), clock.instant());
            if (!source.reviewedSafe() || facts.size() > 10) throw SimulationFailure.invalid();
            UUID runId = fresh(tx, RUNS, ids);
            var canonical = object("requestId", action.toString(), "workflowId", workflowId.toString(),
                    "generation", integer(workflow, "generation"), "runId", runId.toString(),
                    "customerId", workflow.get("customerId"), "policyVersion", terms.policyVersion(),
                    "evidenceFacts", facts.stream().map(f -> object("evidenceId", f.evidenceId().toString(),
                            "kind", f.kind().name(), "result", f.result().name())).toList(),
                    "documents", List.of(object("documentId", source.documentId().toString(),
                            "documentVersion", source.documentVersion(), "contentHash", source.contentHash(), "text", source.text())));
            String inputHash = CanonicalJson.orderedSha256(canonical);
            var input = new LinkedHashMap<String, Object>();
            canonical.forEach((key, value) -> {
                if (key.equals("evidenceFacts")) input.put("inputSnapshotHash", inputHash);
                input.put(key, value);
            });
            var run = object("runId", runId.toString(), "workflowId", workflowId.toString(),
                    "generation", integer(workflow, "generation"), "role", "KYC",
                    "agentId", AGENT_ID, "agentVersion", AGENT_VERSION, "requestId", action.toString(),
                    "inputSnapshotHash", inputHash, "documentId", source.documentId().toString(),
                    "documentVersion", source.documentVersion(), "contentHash", source.contentHash(),
                    "evidenceIds", facts.stream().map(f -> f.evidenceId().toString()).toList());
            int cost = firstCharge(tx, workflowId, "KYC") ? terms.kycPoints() : 0;
            if (!within(tx, workflow, cost)) {
                workflow = block(tx, workflow, action, "RISK_LIMIT_EXCEEDED", "ON_HOLD");
                return receipt(action, workflow);
            }
            tx.put(RUNS, runId.toString(), run);
            charge(tx, workflow, action, "KYC", cost, runId);
            workflow = changed(workflow, "kycRuns", integer(workflow, "kycRuns") + 1,
                    "usedRisk", Math.addExact(integer(workflow, "usedRisk"), cost));
            tx.put(WORKFLOWS, workflowId.toString(), workflow);
            tx.put(JOBS, id(job, "jobId").toString(), changed(job, "state", "RUNNING", "runId", runId.toString()));
            event(tx, workflowId, action, "KYC_INPUT_PREPARED");
            return changed(receipt(action, workflow), "input", CanonicalJson.immutableObject(input));
        });
    }

    /** Ingests a typed synthetic observation. It never trusts model text as evidence. */
    public Map<String, Object> observeKyc(ActorRef actor, UUID action, SimulationSpec.Observation observation) {
        authorizeBeforeReplay(actor, SimulationAccess.Operation.KYC_OBSERVATION, observation.workflowId());
        return journal.execute(actor.actorId(), action, "SIM_OBSERVE_KYC",
                CanonicalJson.sha256(object("requestId", observation.requestId().toString(),
                        "workflowId", observation.workflowId().toString(), "generation", observation.generation(),
                        "runId", observation.runId().toString(), "inputSnapshotHash", observation.inputSnapshotHash(),
                        "status", observation.status().name(),
                        "evidenceIds", observation.evidenceIds().stream().map(UUID::toString).toList())), tx -> {
            var workflow = require(tx, WORKFLOWS, observation.workflowId());
            authorize(actor, SimulationAccess.Operation.KYC_OBSERVATION, workflow);
            requireLegacyLane(tx, workflow);
            var run = require(tx, RUNS, observation.runId());
            if (!sameWorkflow(run, observation.workflowId())
                    || !run.get("requestId").equals(observation.requestId().toString())
                    || integer(run, "generation") != observation.generation()
                    || !run.get("inputSnapshotHash").equals(observation.inputSnapshotHash())) throw SimulationFailure.invalid();
            boolean late = observation.generation() != integer(workflow, "generation")
                    || !"KYC_PENDING".equals(workflow.get("state")) || held(tx, workflow)
                    || tx.rows(RESULTS).values().stream().anyMatch(r -> run.get("runId").equals(r.get("runId")));
            if (late) {
                event(tx, observation.workflowId(), action, "LATE_RESULT_DISCARDED");
                return changed(receipt(action, workflow), "decision", "DENY", "reasonCodes", List.of("LATE_RESULT_DISCARDED"),
                        "message", "LATE_RESULT_DISCARDED");
            }
            final String customerId = (String) workflow.get("customerId");
            var selected = observation.evidenceIds().stream().map(catalog::fact).toList();
            List<String> supplied = strings(run.get("evidenceIds"));
            boolean safe = observation.status() == SimulationSpec.KycStatus.VERIFIED && source(workflow).reviewedSafe()
                    && observation.evidenceIds().stream().allMatch(id -> supplied.contains(id.toString()))
                    && selected.stream().allMatch(f -> f != null && f.customerId().equals(customerId)
                            && f.usable(clock.instant()) && f.result() == SimulationSpec.Outcome.PASS)
                    && selected.stream().map(SimulationSpec.Fact::kind).distinct().count() == 2
                    && supplied.size() == 2
                    && supplied.stream().map(UUID::fromString).map(catalog::fact)
                            .allMatch(f -> f != null && f.usable(clock.instant()) && f.result() == SimulationSpec.Outcome.PASS);
            if (!safe) {
                workflow = block(tx, workflow, action, "KYC_EVIDENCE_REJECTED", "BLOCKED");
                return receipt(action, workflow);
            }
            UUID kycResult = fresh(tx, RESULTS, ids);
            String evidenceHash = CanonicalJson.sha256(observation.evidenceIds().stream().map(UUID::toString).sorted().toList());
            var kycBody = object("status", "VERIFIED", "evidenceIds", observation.evidenceIds().stream().map(UUID::toString).sorted().toList(),
                    "inputSnapshotHash", observation.inputSnapshotHash());
            resultRecording.recordAgentResult(tx, new VirtualResultRecording.AgentResult(
                    kycResult, observation.runId(), new VirtualResultRecording.Scope(observation.workflowId(), observation.generation()),
                    VirtualResultRecording.AgentRole.KYC, kycBody, evidenceHash));
            completeJob(tx, workflow, "SUCCEEDED");
            var app = catalog.application(new WorkflowStartBoundary.Request((String) workflow.get("businessReference"),
                    (String) workflow.get("customerId"), number(workflow, "amountKrw"), id(workflow, "payoutAccountId")));
            UUID loanRun = fresh(tx, RUNS, ids);
            UUID loanResult = fresh(tx, RESULTS, ids);
            int cost = firstCharge(tx, observation.workflowId(), "LOAN") ? terms.loanPoints() : 0;
            if (!within(tx, workflow, cost)) {
                workflow = changed(workflow, "currentKycResultId", kycResult.toString(), "activeJobId", null);
                workflow = block(tx, workflow, action, "RISK_LIMIT_EXCEEDED", "ON_HOLD");
                return receipt(action, workflow);
            }
            boolean recommend = MockLoanRule.recommendsApproval(app.monthlyIncomeKrw(), app.maxLoanAmountKrw(),
                    app.amountKrw(), app.ownsActiveAccount());
            var loanBody = object("approved", recommend, "policyVersion", "LOAN-MOCK-1",
                    "customerId", workflow.get("customerId"), "amountKrw", workflow.get("amountKrw"),
                    "payoutAccountId", workflow.get("payoutAccountId"), "kycResultId", kycResult.toString());
            tx.put(RUNS, loanRun.toString(), object("runId", loanRun.toString(), "workflowId", observation.workflowId().toString(),
                    "generation", observation.generation(), "role", "LOAN", "agentId", "synthetic-loan", "agentVersion", 1,
                    "documentId", run.get("documentId"), "documentVersion", run.get("documentVersion")));
            resultRecording.recordAgentResult(tx, new VirtualResultRecording.AgentResult(
                    loanResult, loanRun, new VirtualResultRecording.Scope(observation.workflowId(), observation.generation()),
                    VirtualResultRecording.AgentRole.LOAN, loanBody, evidenceHash));
            UUID link = fresh(tx, LINKS, ids);
            tx.put(LINKS, link.toString(), object("workflowId", observation.workflowId().toString(),
                    "generation", observation.generation(), "parentRunId", run.get("runId"), "childRunId", loanRun.toString(),
                    "parentResultId", kycResult.toString(), "usableAsAuthorization", false));
            charge(tx, workflow, action, "LOAN", cost, loanRun);
            workflow = changed(workflow, "usedRisk", Math.addExact(integer(workflow, "usedRisk"), cost),
                    "currentKycResultId", kycResult.toString(), "currentLoanResultId", loanResult.toString(), "activeJobId", null);
            workflow = transition(tx, workflow, recommend ? "WAIT_APPROVAL" : "REJECTED",
                    recommend ? "WAIT_APPROVAL" : "DENY", recommend ? "HUMAN_APPROVAL_REQUIRED" : "LOAN_RULE_REJECTED");
            event(tx, observation.workflowId(), action, recommend ? "REVIEW_REQUIRED" : "LOAN_RULE_REJECTED");
            return receipt(action, workflow);
        });
    }

    public Map<String, Object> approvalPreview(ActorRef actor, UUID workflowId) {
        return store.transaction(tx -> {
            var workflow = require(tx, WORKFLOWS, workflowId);
            authorize(actor, SimulationAccess.Operation.REVIEW, workflow);
            return preview(tx, workflow);
        });
    }

    public Map<String, Object> approve(ActorRef actor, UUID action, UUID workflowId,
                                     boolean approved, String snapshotHash, String comment) {
        authorizeBeforeReplay(actor, SimulationAccess.Operation.REVIEW, workflowId);
        if (!SimulationSpec.hash(snapshotHash) || comment == null || comment.length() > 1000) throw SimulationFailure.invalid();
        return notifyPayment(journal.execute(actor.actorId(), action, "SIM_APPROVAL", CanonicalJson.sha256(object(
                "workflowId", workflowId.toString(), "decision", approved ? "APPROVE" : "REJECT",
                "reviewSnapshotHash", snapshotHash, "comment", comment)), tx -> {
            var workflow = require(tx, WORKFLOWS, workflowId);
            authorize(actor, SimulationAccess.Operation.REVIEW, workflow);
            requireLegacyLane(tx, workflow);
            var expected = preview(tx, workflow);
            if (!snapshotHash.equals(expected.get("reviewSnapshotHash"))) throw SimulationFailure.invalid();
            UUID approvalId = fresh(tx, APPROVALS, ids);
            Instant createdAt = clock.instant();
            Instant expiry = createdAt.plus(terms.approvalLifetime());
            int extra = approved ? terms.additionalApprovalLimit() : 0;
            int approvedRiskLimit = approved ? Math.addExact(terms.baseLimit(), extra) : terms.baseLimit();
            var approval = changed(expected, "approvalId", approvalId.toString(), "actorId", actor.actorId(),
                    "status", approved ? "AVAILABLE" : "REJECTED", "expiresAt", expiry.toString(),
                    "extraRiskLimit", extra, "extraRisk", extra, "riskLimit", approvedRiskLimit,
                    "createdAt", createdAt.toString());
            tx.put(APPROVALS, approvalId.toString(), approval);
            workflow = changed(workflow, "riskLimit", approvedRiskLimit);
            workflow = transition(tx, workflow, approved ? "APPROVED" : "REJECTED", "ALLOW", approved ? "APPROVAL_RECORDED" : "REJECTION_RECORDED");
            UUID job = approved ? job(tx, workflow, "PAY", approvalId) : null;
            workflow = changed(workflow, "activeJobId", job == null ? null : job.toString());
            tx.put(WORKFLOWS, workflowId.toString(), workflow);
            event(tx, workflowId, action, approved ? "APPROVAL_RECORDED" : "REJECTION_RECORDED");
            return changed(receipt(action, workflow), "approvalId", approvalId.toString(),
                    "extraRiskLimit", extra, "riskLimit", integer(workflow, "riskLimit"),
                    "expiresAt", expiry.toString(), "payJobId", job == null ? null : job.toString());
        }));
    }

    /** First half of a simulated payment; no money is transferred. */
    public Map<String, Object> reservePayment(ActorRef actor, UUID action, UUID workflowId) {
        return reservePayment(actor, action, workflowId, null, 0);
    }
    /** Expected queued-job binding is checked before history and again in the mutation transaction. */
    public Map<String, Object> reservePayment(ActorRef actor, UUID action, UUID workflowId, UUID expectedJobId, int expectedGeneration) {
        authorizeBeforeReplay(actor, SimulationAccess.Operation.PAYMENT, workflowId);
        var payload = deliveryPayload(workflowId, expectedJobId, expectedGeneration);
        if (expectedJobId != null) store.transaction(tx -> {
            var current = require(tx, WORKFLOWS, workflowId);
            authorize(actor, SimulationAccess.Operation.PAYMENT, current);
            requireExpectedJob(tx, current, expectedJobId, expectedGeneration, "PAY"); return null;
        });
        return journal.execute(actor.actorId(), action, "SIM_RESERVE_PAYMENT",
                CanonicalJson.sha256(payload), tx -> {
            var workflow = require(tx, WORKFLOWS, workflowId);
            authorize(actor, SimulationAccess.Operation.PAYMENT, workflow);
            requireLegacyLane(tx, workflow);
            requireExpectedJob(tx, workflow, expectedJobId, expectedGeneration, "PAY");
            if (!"APPROVED".equals(workflow.get("state")) || held(tx, workflow)) throw SimulationFailure.invalid();
            var job = require(tx, JOBS, id(workflow, "activeJobId"));
            var approval = require(tx, APPROVALS, id(job, "approvalId"));
            if (!validApproval(tx, workflow, approval) || !within(tx, workflow, terms.payPoints())) {
                workflow = block(tx, workflow, action, "PAYMENT_PRECONDITION_FAILED", "ON_HOLD");
                return receipt(action, workflow);
            }
            UUID reservationId = fresh(tx, RESERVATIONS, ids), runId = fresh(tx, RUNS, ids);
            var reservation = object("reservationId", reservationId.toString(), "workflowId", workflowId.toString(),
                    "generation", integer(workflow, "generation"), "jobId", job.get("jobId"), "approvalId", approval.get("approvalId"),
                    "runId", runId.toString(), "points", terms.payPoints(), "status", "RESERVED",
                    "bindingHash", paymentBinding(workflow, approval));
            tx.put(RESERVATIONS, reservationId.toString(), reservation);
            tx.put(RUNS, runId.toString(), object("runId", runId.toString(), "workflowId", workflowId.toString(),
                    "generation", integer(workflow, "generation"), "role", "PAYMENT", "agentId", "synthetic-payment", "agentVersion", 1,
                    "documentId", workflow.get("documentId"), "documentVersion", workflow.get("documentVersion")));
            var loanResult = require(tx, RESULTS, id(workflow, "currentLoanResultId"));
            UUID link = fresh(tx, LINKS, ids);
            tx.put(LINKS, link.toString(), object("workflowId", workflowId.toString(), "generation", integer(workflow, "generation"),
                    "parentRunId", loanResult.get("runId"), "childRunId", runId.toString(), "parentResultId", loanResult.get("resultId"),
                    "usableAsAuthorization", false));
            tx.put(APPROVALS, id(approval, "approvalId").toString(), changed(approval, "status", "RESERVED"));
            tx.put(JOBS, id(job, "jobId").toString(), changed(job, "state", "RUNNING", "runId", runId.toString()));
            risk(tx, workflow, action, "PAYMENT", "RESERVE", terms.payPoints(), runId, reservationId);
            workflow = changed(workflow, "reservedRisk", Math.addExact(integer(workflow, "reservedRisk"), terms.payPoints()));
            workflow = transition(tx, workflow, "PAYMENT_RESERVED", "ALLOW", "PAYMENT_RESERVED");
            return changed(receipt(action, workflow), "reservationId", reservationId.toString());
        });
    }

    /** Commit rechecks every current binding and hold after reservation, within one virtual transaction. */
    public Map<String, Object> commitPayment(ActorRef actor, UUID action, UUID workflowId, UUID reservationId) {
        authorizeBeforeReplay(actor, SimulationAccess.Operation.PAYMENT, workflowId);
        return journal.execute(actor.actorId(), action, "SIM_COMMIT_PAYMENT",
                CanonicalJson.sha256(object("workflowId", workflowId.toString(), "reservationId", reservationId.toString())), tx -> {
            var workflow = require(tx, WORKFLOWS, workflowId);
            authorize(actor, SimulationAccess.Operation.PAYMENT, workflow);
            requireLegacyLane(tx, workflow);
            var reservation = require(tx, RESERVATIONS, reservationId);
            // A late reservation is not authority to invalidate a newer independent generation.
            if (!sameWorkflow(reservation, workflowId)
                    || integer(reservation, "generation") != integer(workflow, "generation"))
                throw SimulationFailure.invalid();
            var approval = require(tx, APPROVALS, id(reservation, "approvalId"));
            boolean valid = "PAYMENT_RESERVED".equals(workflow.get("state")) && !held(tx, workflow)
                    && "RESERVED".equals(reservation.get("status")) && validApproval(tx, workflow, approval)
                    && "RESERVED".equals(approval.get("status"))
                    && reservation.get("bindingHash").equals(paymentBinding(workflow, approval))
                    && within(tx, workflow, 0);
            if (!valid) {
                if (!"PAID".equals(workflow.get("state"))) workflow = block(tx, workflow, action, "PAYMENT_PRECONDITION_FAILED", "ON_HOLD");
                return changed(receipt(action, workflow), "decision", "DENY", "reasonCodes", List.of("PAYMENT_PRECONDITION_FAILED"),
                        "message", "PAYMENT_PRECONDITION_FAILED");
            }
            if (!forWorkflow(tx, PAYMENTS, workflowId).isEmpty()) throw SimulationFailure.invalid();
            UUID payment = fresh(tx, PAYMENTS, ids);
            resultRecording.recordMockPayment(tx, new VirtualResultRecording.MockPayment(
                    payment, id(reservation, "runId"), action,
                    new VirtualResultRecording.Scope(workflowId, integer(workflow, "generation")),
                    reservationId, id(approval, "approvalId"), (String) workflow.get("customerId"),
                    number(workflow, "amountKrw"), id(workflow, "payoutAccountId"), clock.instant()));
            tx.put(RESERVATIONS, reservationId.toString(), changed(reservation, "status", "COMMITTED"));
            tx.put(APPROVALS, id(approval, "approvalId").toString(), changed(approval, "status", "CONSUMED"));
            completeJob(tx, workflow, "SUCCEEDED");
            int points = integer(reservation, "points");
            risk(tx, workflow, action, "PAYMENT", "CONSUME", points, id(reservation, "runId"), reservationId);
            workflow = changed(workflow, "usedRisk", Math.addExact(integer(workflow, "usedRisk"), points),
                    "reservedRisk", Math.subtractExact(integer(workflow, "reservedRisk"), points), "activeJobId", null,
                    "riskLimit", terms.baseLimit());
            workflow = transition(tx, workflow, "PAID", "ALLOW", "PAYMENT_COMMITTED");
            event(tx, workflowId, action, "PAYMENT_COMMITTED");
            return changed(receipt(action, workflow), "paymentId", payment.toString());
        });
    }

    public Map<String, Object> get(ActorRef actor, UUID workflowId) {
        return store.transaction(tx -> {
            var workflow = require(tx, WORKFLOWS, workflowId); authorize(actor, SimulationAccess.Operation.READ, workflow);
            return view(tx, workflow);
        });
    }
    /** Preserved no-filter entry point. */
    public Map<String, Object> list(ActorRef actor, int page, int size) {
        return list(actor, "", page, size);
    }

    /** Exact public workflow-state filter; authorization precedes filtering, counting and pagination. */
    public Map<String, Object> list(ActorRef actor, String state, int page, int size) {
        if (page < 0 || size < 1 || size > 100 || state == null) throw SimulationFailure.invalid();
        if (!state.isEmpty()) {
            try { WorkflowHttpController.State.valueOf(state); }
            catch (IllegalArgumentException invalidState) { throw SimulationFailure.invalid(); }
        }
        access.require(actor, SimulationAccess.Operation.READ, null, null);
        return store.transaction(tx -> {
            // Every item is separately authorized; a broad READ decision cannot bypass ownership.
            var rows = tx.rows(WORKFLOWS).values().stream().sorted(java.util.Comparator.comparing(w -> (String) w.get("workflowId"))).toList();
            var visible = new ArrayList<Map<String, Object>>();
            for (var row : rows) {
                try {
                    authorize(actor, SimulationAccess.Operation.READ, row);
                    if (state.isEmpty() || state.equals(row.get("state"))) visible.add(view(tx, row));
                } catch (SimulationFailure denied) {
                    if (denied.status() != 403) throw denied;
                }
            }
            long offset = (long) page * size;
            return object("items", visible.stream().skip(offset).limit(size).toList(), "total", visible.size(), "page", page, "size", size,
                    "executionMode", VirtualTransactionalStore.MODE);
        });
    }
    public Map<String, Object> trace(ActorRef actor, UUID workflowId) {
        return store.transaction(tx -> {
            var workflow = require(tx, WORKFLOWS, workflowId); authorize(actor, SimulationAccess.Operation.READ, workflow);
            try {
                var scope = new VirtualWorkflowLane.Scope(id(workflow, "workflowId"), integer(workflow, "generation"),
                        (String) workflow.get("customerId"));
                if (TypedWorkflowTraceProjection.applies(tx, scope))
                    return TypedWorkflowTraceProjection.project(tx, scope, catalog, clock.instant());
            } catch (RuntimeException unavailable) {
                throw SimulationFailure.unavailable();
            }
            var runs = forWorkflow(tx, RUNS, workflowId);
            var sourceUses = runs.stream().filter(r -> r.containsKey("contentHash")).map(r -> object("runId", r.get("runId"),
                    "documentId", r.get("documentId"), "documentVersion", r.get("documentVersion"), "contentHash", r.get("contentHash"))).toList();
            var evidenceUses = runs.stream().filter(r -> r.containsKey("evidenceIds")).flatMap(r -> strings(r.get("evidenceIds")).stream())
                    .distinct().map(UUID::fromString).map(catalog::fact).filter(Objects::nonNull).map(f -> object(
                            "evidenceId", f.evidenceId().toString(), "kind", f.kind().name(), "result", f.result().name(),
                            "issuedAt", f.issuedAt().toString(), "expiresAt", f.expiresAt().toString(),
                            "temporalStatus", clock.instant().isBefore(f.issuedAt()) ? "NOT_YET_ISSUED" :
                                    !clock.instant().isBefore(f.expiresAt()) ? "EXPIRED" : "WITHIN_PERIOD")).toList();
            return object("workflowId", workflowId.toString(), "generation", workflow.get("generation"), "runs", runs,
                    "results", forWorkflow(tx, RESULTS, workflowId), "grants", List.of(), "dependencies", forWorkflow(tx, LINKS, workflowId),
                    "approvals", forWorkflow(tx, APPROVALS, workflowId), "riskEvents", forWorkflow(tx, RISK, workflowId),
                    "payments", forWorkflow(tx, PAYMENTS, workflowId), "auditEvents", forWorkflow(tx, AUDIT, workflowId),
                    "sourceUses", sourceUses, "evidenceUses", evidenceUses, "evidenceCheckedAt", clock.instant().toString(),
                    "executionMode", VirtualTransactionalStore.MODE, "cryptographicAuthorityImplemented", false);
        });
    }

    private Map<String, Object> preview(TransactionalStore.Tx tx, Map<String, Object> workflow) {
        if (!"WAIT_APPROVAL".equals(workflow.get("state")) || held(tx, workflow)
                || workflow.get("currentKycResultId") == null || workflow.get("currentLoanResultId") == null)
            throw SimulationFailure.invalid();
        var kyc = require(tx, RESULTS, id(workflow, "currentKycResultId"));
        var loan = require(tx, RESULTS, id(workflow, "currentLoanResultId"));
        if (!currentEvidence(tx, workflow, kyc)) throw SimulationFailure.invalid();
        var snapshot = object("workflowId", workflow.get("workflowId"), "generation", workflow.get("generation"),
                "customerId", workflow.get("customerId"), "amountKrw", workflow.get("amountKrw"),
                "payoutAccountId", workflow.get("payoutAccountId"), "kycResultId", kyc.get("resultId"),
                "loanResultId", loan.get("resultId"), "evidenceBundleHash", kyc.get("evidenceBundleHash"),
                "loanResultHash", loan.get("resultHash"), "policyVersion", terms.policyVersion(),
                "usedRisk", workflow.get("usedRisk"), "reservedRisk", workflow.get("reservedRisk"),
                "riskLimitAfterApproval", Math.addExact(terms.baseLimit(), terms.additionalApprovalLimit()));
        return changed(snapshot, "reviewSnapshotHash", CanonicalJson.sha256(snapshot));
    }
    private boolean validApproval(TransactionalStore.Tx tx, Map<String, Object> workflow, Map<String, Object> approval) {
        if (!("AVAILABLE".equals(approval.get("status")) || "RESERVED".equals(approval.get("status")))
                || !clock.instant().isBefore(Instant.parse((String) approval.get("expiresAt")))
                || !approval.get("workflowId").equals(workflow.get("workflowId"))
                || integer(approval, "generation") != integer(workflow, "generation")
                || !approval.get("customerId").equals(workflow.get("customerId"))
                || number(approval, "amountKrw") != number(workflow, "amountKrw")
                || !approval.get("payoutAccountId").equals(workflow.get("payoutAccountId"))
                || !approval.get("kycResultId").equals(workflow.get("currentKycResultId"))
                || !approval.get("loanResultId").equals(workflow.get("currentLoanResultId"))
                || !terms.policyVersion().equals(approval.get("policyVersion"))
                || !Integer.valueOf(terms.additionalApprovalLimit()).equals(approval.get("extraRisk"))
                || !Integer.valueOf(Math.addExact(terms.baseLimit(), terms.additionalApprovalLimit())).equals(approval.get("riskLimit")))
            return false;
        var kyc = require(tx, RESULTS, id(workflow, "currentKycResultId"));
        var loan = require(tx, RESULTS, id(workflow, "currentLoanResultId"));
        return currentEvidence(tx, workflow, kyc) && approval.get("evidenceBundleHash").equals(kyc.get("evidenceBundleHash"))
                && approval.get("loanResultHash").equals(loan.get("resultHash"));
    }
    @SuppressWarnings("unchecked")
    private boolean currentEvidence(TransactionalStore.Tx tx, Map<String, Object> workflow, Map<String, Object> kyc) {
        var body = (Map<String, Object>) kyc.get("body");
        return strings(body.get("evidenceIds")).stream().map(UUID::fromString).map(catalog::fact)
                .allMatch(f -> f != null && f.customerId().equals(workflow.get("customerId"))
                        && f.usable(clock.instant()) && f.result() == SimulationSpec.Outcome.PASS)
                && source(workflow).reviewedSafe();
    }
    private String paymentBinding(Map<String, Object> workflow, Map<String, Object> approval) {
        return CanonicalJson.sha256(object("workflowId", workflow.get("workflowId"), "generation", workflow.get("generation"),
                "customerId", workflow.get("customerId"), "amountKrw", workflow.get("amountKrw"),
                "payoutAccountId", workflow.get("payoutAccountId"), "approvalId", approval.get("approvalId"),
                "kycResultId", approval.get("kycResultId"), "loanResultId", approval.get("loanResultId"),
                "evidenceBundleHash", approval.get("evidenceBundleHash"), "loanResultHash", approval.get("loanResultHash"),
                "policyVersion", approval.get("policyVersion")));
    }
    private SimulationSpec.Source source(Map<String, Object> workflow) {
        var source = catalog.source(id(workflow, "documentId"), integer(workflow, "documentVersion"));
        if (source == null) throw SimulationFailure.invalid();
        return source;
    }
    private static void requireLegacyLane(TransactionalStore.Tx tx, Map<String, Object> workflow) {
        VirtualWorkflowLane.requireLegacy(tx, new VirtualWorkflowLane.Scope(
                id(workflow, "workflowId"), integer(workflow, "generation"), (String) workflow.get("customerId")));
    }

    private void authorizeBeforeReplay(ActorRef actor, SimulationAccess.Operation op, UUID workflowId) {
        store.transaction(tx -> {
            authorize(actor, op, require(tx, WORKFLOWS, workflowId));
            return null;
        });
    }
    private void authorize(ActorRef actor, SimulationAccess.Operation op, Map<String, Object> workflow) {
        access.require(actor, op, id(workflow, "workflowId"), (String) workflow.get("customerId"));
    }
    boolean held(TransactionalStore.Tx tx, Map<String, Object> workflow) {
        return tx.rows(QUARANTINES).values().stream().anyMatch(q -> "ACTIVE".equals(q.get("status")) && matches(tx, workflow, q));
    }
    @SuppressWarnings("unchecked")
    boolean matches(TransactionalStore.Tx tx, Map<String, Object> workflow, Map<String, Object> quarantine) {
        var target = (Map<String, Object>) quarantine.get("target");
        int generation = integer(workflow, "generation");
        var currentRuns = forWorkflow(tx, RUNS, id(workflow, "workflowId")).stream()
                .filter(r -> integer(r, "generation") == generation).toList();
        return switch ((String) quarantine.get("scope")) {
            case "WORKFLOW" -> workflow.get("workflowId").equals(target.get("workflowId"));
            case "SOURCE_VERSION" -> workflow.get("documentId").equals(target.get("documentId"))
                    && integer(workflow, "documentVersion") == integer(target, "documentVersion")
                    || currentRuns.stream().anyMatch(r -> target.get("documentId").equals(r.get("documentId"))
                            && target.get("documentVersion").equals(r.get("documentVersion")));
            // All supported virtual stage agents are known before their first run.
            case "AGENT_VERSION" -> List.of(AGENT_ID, "synthetic-loan", "synthetic-payment").contains(target.get("agentId"))
                    && integer(target, "agentVersion") == 1;
            case "RUN" -> currentRuns.stream().anyMatch(r -> r.get("runId").equals(target.get("runId")));
            case "RESULT" -> {
                var result = tx.get(RESULTS, (String) target.get("resultId"));
                yield result != null && sameWorkflow(result, id(workflow, "workflowId")) && integer(result, "generation") == generation;
            }
            default -> throw SimulationFailure.invalid();
        };
    }
    Map<String, Object> block(TransactionalStore.Tx tx, Map<String, Object> workflow, UUID action, String reason, String state) {
        if ("PAID".equals(workflow.get("state"))) return workflow;
        invalidate(tx, workflow, action, reason);
        workflow = changed(workflow, "reservedRisk", 0, "activeJobId", null, "riskLimit", terms.baseLimit());
        return transition(tx, workflow, state, "DENY", reason);
    }
    private void invalidate(TransactionalStore.Tx tx, Map<String, Object> workflow, UUID action, String reason) {
        UUID workflowId = id(workflow, "workflowId");
        for (var reservation : forWorkflow(tx, RESERVATIONS, workflowId)) {
            if ("RESERVED".equals(reservation.get("status"))) {
                tx.put(RESERVATIONS, id(reservation, "reservationId").toString(), changed(reservation, "status", "RELEASED"));
                risk(tx, workflow, action, "PAYMENT", "RELEASE", integer(reservation, "points"), id(reservation, "runId"), id(reservation, "reservationId"));
            }
        }
        for (var approval : forWorkflow(tx, APPROVALS, workflowId)) {
            if ("AVAILABLE".equals(approval.get("status")) || "RESERVED".equals(approval.get("status")))
                tx.put(APPROVALS, id(approval, "approvalId").toString(), changed(approval, "status", "REVOKED"));
        }
        completeJob(tx, workflow, "FAILED");
        event(tx, workflowId, action, reason);
    }
    private Map<String, Object> transition(TransactionalStore.Tx tx, Map<String, Object> workflow, String state, String decision, String reason) {
        var changed = changed(workflow, "state", state, "lastDecision", decision, "reasonCodes", List.of(reason));
        tx.put(WORKFLOWS, id(workflow, "workflowId").toString(), changed); return changed;
    }
    private UUID job(TransactionalStore.Tx tx, Map<String, Object> workflow, String phase, UUID approval) {
        UUID id = fresh(tx, JOBS, ids);
        tx.put(JOBS, id.toString(), object("jobId", id.toString(), "workflowId", workflow.get("workflowId"),
                "generation", workflow.get("generation"), "phase", phase, "state", "PENDING",
                "runId", null, "approvalId", approval == null ? null : approval.toString()));
        return id;
    }
    private void completeJob(TransactionalStore.Tx tx, Map<String, Object> workflow, String state) {
        if (workflow.get("activeJobId") != null) {
            UUID id = id(workflow, "activeJobId");
            var job = require(tx, JOBS, id);
            if ("PENDING".equals(job.get("state")) || "RUNNING".equals(job.get("state")))
                tx.put(JOBS, id.toString(), changed(job, "state", state));
        }
    }
    /** Current permission cap is derived from an exact live approval, never from a cached workflow number. */
    private int effectiveRiskLimit(TransactionalStore.Tx tx, Map<String, Object> workflow) {
        if ("PAID".equals(workflow.get("state")) || held(tx, workflow)) return terms.baseLimit();
        for (var approval : forWorkflow(tx, APPROVALS, id(workflow, "workflowId"))) {
            if (validApproval(tx, workflow, approval)) return integer(approval, "riskLimit");
        }
        return terms.baseLimit();
    }
    private boolean within(TransactionalStore.Tx tx, Map<String, Object> workflow, int points) {
        return (long) integer(workflow, "usedRisk") + integer(workflow, "reservedRisk") + points <= effectiveRiskLimit(tx, workflow);
    }
    /** Historical display only: the completed payment must point to this consumed approval. */
    private Integer historicalApprovedRiskLimit(TransactionalStore.Tx tx, Map<String, Object> workflow) {
        if (!"PAID".equals(workflow.get("state"))) return null;
        UUID workflowId = id(workflow, "workflowId");
        for (var payment : forWorkflow(tx, PAYMENTS, workflowId)) {
            if (integer(payment, "generation") != integer(workflow, "generation")) continue;
            var approval = tx.get(APPROVALS, (String) payment.get("approvalId"));
            if (approval != null && "CONSUMED".equals(approval.get("status"))
                    && sameWorkflow(approval, workflowId)
                    && payment.get("approvalId").equals(approval.get("approvalId"))
                    && integer(approval, "generation") == integer(payment, "generation")
                    && approval.get("riskLimit") instanceof Integer limit && limit >= 0) return limit;
        }
        return null;
    }
    private boolean firstCharge(TransactionalStore.Tx tx, UUID workflow, String stage) {
        return forWorkflow(tx, RISK, workflow).stream().noneMatch(r -> "CHARGE".equals(r.get("eventType")) && stage.equals(r.get("stage")));
    }
    private void charge(TransactionalStore.Tx tx, Map<String, Object> workflow, UUID action, String stage, int points, UUID run) {
        if (points > 0) risk(tx, workflow, action, stage, "CHARGE", points, run, null);
    }
    private void risk(TransactionalStore.Tx tx, Map<String, Object> workflow, UUID action, String stage, String type, int points, UUID run, UUID reservation) {
        UUID id = fresh(tx, RISK, ids);
        tx.put(RISK, id.toString(), object("riskEventId", id.toString(), "workflowId", workflow.get("workflowId"),
                "generation", workflow.get("generation"), "stage", stage, "eventType", type, "points", points,
                "actionId", action.toString(), "runId", run.toString(), "reservationId", reservation == null ? null : reservation.toString()));
    }
    void event(TransactionalStore.Tx tx, UUID workflow, UUID action, String type) {
        UUID id = fresh(tx, AUDIT, ids);
        tx.put(AUDIT, id.toString(), object("auditEventId", id.toString(), "workflowId", workflow.toString(),
                "actionId", action.toString(), "eventType", type, "createdAt", clock.instant().toString()));
    }
    /** Independent resume never reuses historical run/result dependencies. */
    private boolean resumeScopeClear(TransactionalStore.Tx tx, Map<String, Object> workflow) {
        int generation = integer(workflow, "generation");
        // No candidate generation exists at MAX; public readiness must fail closed too.
        return generation < Integer.MAX_VALUE
                && !held(tx, changed(workflow, "generation", generation + 1));
    }
    private Map<String, Object> view(TransactionalStore.Tx tx, Map<String, Object> workflow) {
        // get/list have already authorized this exact workflow/customer before derived joins.
        try {
            var scope = new VirtualWorkflowLane.Scope(id(workflow, "workflowId"), integer(workflow, "generation"),
                    (String) workflow.get("customerId"));
            if (TypedWorkflowReadProjection.applies(tx, scope))
                return TypedWorkflowReadProjection.project(tx, scope, catalog, clock.instant());
        } catch (RuntimeException unavailable) {
            throw SimulationFailure.unavailable();
        }
        var result = new LinkedHashMap<String, Object>(workflow);
        result.remove("documentId"); result.remove("documentVersion"); result.remove("activeJobId");
        result.put("riskLimit", effectiveRiskLimit(tx, workflow));
        if ("PAID".equals(workflow.get("state")))
            result.put("historicalApprovedRiskLimit", historicalApprovedRiskLimit(tx, workflow));
        result.put("activeJob", workflow.get("activeJobId") == null ? null : require(tx, JOBS, id(workflow, "activeJobId")));
        result.put("activeQuarantines", tx.rows(QUARANTINES).values().stream()
                .filter(q -> "ACTIVE".equals(q.get("status")) && matches(tx, workflow, q)).map(q -> q.get("quarantineId")).toList());
        boolean evidenceReady = workflow.get("currentKycResultId") != null
                && currentEvidence(tx, workflow, require(tx, RESULTS, id(workflow, "currentKycResultId")));
        result.put("canApprove", "WAIT_APPROVAL".equals(workflow.get("state")) && !held(tx, workflow) && evidenceReady);
        result.put("canResume", List.of("BLOCKED", "ON_HOLD").contains(workflow.get("state"))
                && resumeScopeClear(tx, workflow) && source(workflow).reviewedSafe() && workflow.get("activeJobId") == null
                && integer(workflow, "kycRuns") < terms.maxAutomaticKycRuns());
        result.put("resumeCapability", "LEGACY_HTTP");
        result.put("executionMode", VirtualTransactionalStore.MODE);
        return CanonicalJson.immutableObject(result);
    }
    private static Map<String, Object> deliveryPayload(UUID workflowId, UUID jobId, int generation) {
        if (jobId == null) {
            if (generation != 0) throw SimulationFailure.invalid();
            return object("workflowId", workflowId.toString());
        }
        if (generation < 1) throw SimulationFailure.invalid();
        return object("workflowId", workflowId.toString(), "expectedJobId", jobId.toString(), "expectedGeneration", generation);
    }
    private static void requireExpectedJob(TransactionalStore.Tx tx, Map<String, Object> workflow,
            UUID jobId, int generation, String phase) {
        if (jobId == null) return;
        if (!Integer.valueOf(generation).equals(workflow.get("generation"))
                || !jobId.toString().equals(workflow.get("activeJobId"))) throw SimulationFailure.invalid();
        var job = require(tx, JOBS, jobId);
        if (!workflow.get("workflowId").equals(job.get("workflowId"))
                || !Integer.valueOf(generation).equals(job.get("generation"))
                || !phase.equals(job.get("phase")) || !"PENDING".equals(job.get("state"))) throw SimulationFailure.invalid();
    }
    private WorkflowHttpController.Receipt notifyKyc(WorkflowHttpController.Receipt receipt) {
        if (delivery != null && receipt.decision() == WorkflowHttpController.Decision.ALLOW
                && receipt.state() == WorkflowHttpController.State.KYC_PENDING) {
            try { delivery.kycCommitted(receipt.workflowId(), receipt.generation()); }
            catch (RuntimeException unavailable) { /* The action receipt is already committed; no dispatch retry here. */ }
        }
        return receipt;
    }
    private Map<String, Object> notifyPayment(Map<String, Object> receipt) {
        if (delivery != null && "ALLOW".equals(receipt.get("decision")) && "APPROVED".equals(receipt.get("state"))) {
            try { delivery.paymentCommitted(id(receipt, "workflowId"), integer(receipt, "generation")); }
            catch (RuntimeException unavailable) { /* Dispatch admission never relabels a known action commit. */ }
        }
        return receipt;
    }
    static Map<String, Object> receipt(UUID action, Map<String, Object> workflow) {
        List<String> reasons = strings(workflow.get("reasonCodes"));
        return object("requestId", action.toString(), "workflowId", workflow.get("workflowId"),
                "generation", workflow.get("generation"), "state", workflow.get("state"),
                "decision", workflow.get("lastDecision"), "reasonCodes", reasons,
                "message", reasons.isEmpty() ? "VIRTUAL_ACCEPTED" : reasons.get(0), "replayed", false);
    }
    private static WorkflowHttpController.Receipt wire(Map<String, Object> value) {
        return new WorkflowHttpController.Receipt(id(value, "requestId"), id(value, "workflowId"), integer(value, "generation"),
                WorkflowHttpController.State.valueOf((String) value.get("state")),
                WorkflowHttpController.Decision.valueOf((String) value.get("decision")), strings(value.get("reasonCodes")),
                (String) value.get("message"), (Boolean) value.get("replayed"),
                value.get("kycJobId") == null ? null : id(value, "kycJobId"));
    }
}
