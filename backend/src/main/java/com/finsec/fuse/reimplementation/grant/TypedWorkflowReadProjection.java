package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.WorkflowHttpController;
import com.finsec.fuse.reimplementation.WorkflowStartBoundary;
import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import com.finsec.fuse.reimplementation.simulation.SimulationFailure;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import com.finsec.fuse.reimplementation.simulation.VirtualGrantWorkflowControl;
import com.finsec.fuse.reimplementation.simulation.VirtualQuarantineService;
import com.finsec.fuse.reimplementation.simulation.VirtualWorkflowLane.Scope;
import java.time.Instant;
import java.util.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentTransactionBinding.*;

/** Safe workflow metadata only. The caller must authorize READ before invoking either entry. */
public final class TypedWorkflowReadProjection {
    private TypedWorkflowReadProjection() { }
    private static final String WORKFLOWS="virtual_workflows", LANES="virtual_workflow_lanes",
            GRANTS="virtual_grant_profile_grants", PREPARATIONS="virtual_grant_profile_kyc_preparations",
            CHARGES="virtual_grant_profile_stage_charges", RISK="virtual_grant_profile_payment_risk_reservations",
            APPROVALS="virtual_grant_profile_review_approvals";
    private static final List<String> PUBLIC_FIELDS=List.of("workflowId","generation","state","businessReference","customerId",
            "amountKrw","payoutAccountId","usedRisk","reservedRisk","riskLimit","kycRuns","currentKycResultId",
            "currentLoanResultId","reasonCodes","lastDecision","policyVersion");
    private static final Set<String> REASONS=Set.of("RESUME_BLOCKED","QUARANTINE_ACTIVE","KYC_PRECONDITION_FAILED",
            "RISK_LIMIT_EXCEEDED","APPROVAL_RECORDED","REJECTION_RECORDED","PAYMENT_RESERVED","PAYMENT_COMMITTED",
            "HUMAN_APPROVAL_REQUIRED","LOAN_RULE_REJECTED","KYC_NEGATIVE_EVALUATION");

    /** Known legacy is false; malformed or missing typed-lane state never falls back to legacy. */
    public static boolean applies(TransactionalStore.Tx tx, Scope expected) {
        try {
            var w=workflow(tx,expected);var lane=tx.get(LANES,expected.workflowId().toString());
            if(lane==null){if(w.containsKey("typedStageAgents"))throw bad();return false;}
            if(!lane.keySet().equals(Set.of("workflowId","generation","customerId","lane")))throw bad();
            requireScope(lane,expected);
            if("TYPED".equals(lane.get("lane")))return true;
            if("LEGACY".equals(lane.get("lane"))&&!w.containsKey("typedStageAgents"))return false;
            throw bad();
        } catch(RuntimeException unconfirmed){throw bad();}
    }

    /** Borrowed same-transaction reader; no transaction, mutation, body decoding or authority is created. */
    public static Map<String,Object> project(TransactionalStore.Tx tx, Scope expected,
                                             SimulationSpec.Catalog catalog, Instant now) {
        try {
            if(catalog==null||now==null||!applies(tx,expected))throw bad();
            var w=workflow(tx,expected);var keys=new HashSet<>(PUBLIC_FIELDS);
            keys.addAll(Set.of("documentId","documentVersion","activeJobId","typedStageAgents"));
            if(!w.keySet().equals(keys))throw bad();
            WorkflowHttpController.State.valueOf(text(w,"state"));WorkflowHttpController.Decision.valueOf(text(w,"lastDecision"));
            text(w,"businessReference");text(w,"policyVersion");uuid(w,"payoutAccountId");
            if(!(w.get("amountKrw") instanceof Long amount)||amount<1||amount>50000000L)throw bad();
            var reasons=list(w.get("reasonCodes"));for(var reason:reasons)if(!(reason instanceof String r)||!REASONS.contains(r))throw bad();
            var origin=VirtualGrantGenerationHistory.requireCurrent(tx,expected);var terms=origin.terms();
            if(!terms.policyVersion().equals(w.get("policyVersion")))throw bad();
            uuid(w,"documentId");positive(w,"documentVersion");
            var refs=references(tx,expected);var current=refs.values().stream().filter(r->r.generation()==expected.generation()).toList();
            if(current.isEmpty())throw bad();
            var agents=agents(w);
            var rootPlan=map(tx.get("virtual_grant_profile_root_material",origin.rootGrantId().toString()).get("workflowPlan"));
            var originalApp=map(rootPlan.get("application"));
            for(var key:List.of("businessReference","customerId","amountKrw","payoutAccountId"))if(!w.get(key).equals(originalApp.get(key)))throw bad();
            if(!w.get("typedStageAgents").equals(rootPlan.get("stageAgents")))throw bad();
            var active=new ArrayList<String>();boolean held=false;
            for(var e:tx.rows("virtual_quarantines").entrySet()) {
                if(!Set.of("ACTIVE","RELEASED").contains(e.getValue().get("status")))throw bad();
                if(!"ACTIVE".equals(e.getValue().get("status")))continue;
                if(!e.getKey().equals(uuid(e.getValue(),"quarantineId").toString()))throw bad();
                var target=target(e.getValue());if(matches(target,expected,w,agents,current,refs)) {active.add(e.getKey());held=true;}
            }
            active.sort(String::compareTo);
            for(var r:current) {
                var raw=tx.get(GRANTS,r.grantId().toString());
                if("CONSUMED".equals(raw.get("state")))VirtualGrantTransactionJournal.readResultMetadata(tx,expected,r.resultId(),AllowedAction.valueOf(text(raw,"action")));
            }
            nonnegative(w,"riskLimit");
            var counts=counts(tx,expected,terms,refs);
            if(counts.used()!=nonnegative(w,"usedRisk")||counts.reserved()!=nonnegative(w,"reservedRisk")||counts.runs()!=nonnegative(w,"kycRuns"))throw bad();
            var kyc=currentResult(tx,w,expected,"currentKycResultId",AllowedAction.EVALUATE_KYC);
            var loan=currentResult(tx,w,expected,"currentLoanResultId",AllowedAction.CREATE_LOAN_RECOMMENDATION);
            if(loan!=null&&(kyc==null||!loan.reference().sourceRunId().equals(kyc.reference().targetRunId())
                    ||!loan.reference().sourceResultId().equals(uuidFrom(w.get("currentKycResultId")))))throw bad();
            Integer historical=null;int limit=terms.baseLimit();
            for(var e:tx.rows(APPROVALS).entrySet()) {
                var raw=e.getValue();var material=map(raw.get("material"));var scope=map(material.get("scope"));
                if(!expected.workflowId().toString().equals(scope.get("workflowId")))continue;
                var approval=VirtualGrantTransactionJournal.readApprovalMetadata(tx,UUID.fromString(e.getKey()));
                validateApproval(tx,approval,expected,terms,refs);
                invalidated(tx,"virtual_grant_profile_approval_invalidations",approval.approvalId(),"approval",raw);
                if(approval.material().scope().generation()!=expected.generation())continue;
                if("PAID".equals(w.get("state"))&&approval.state()==ApprovalPlanState.CONSUMED) {
                    if(historical!=null)throw bad();historical=approval.riskLimit();
                }
                // Without an actual selected-evidence snapshot no elevated current cap is inferred.

            }
            if("PAID".equals(w.get("state"))&&(historical==null||!counts.paid()))throw bad();
            var job=job(tx,w,expected);boolean canResume=false;
            if(("BLOCKED".equals(w.get("state"))||"ON_HOLD".equals(w.get("state")))&&expected.generation()<Integer.MAX_VALUE
                    &&counts.runs()<terms.maxAutomaticKycRuns()&&job==null&&counts.reserved()==0&&!counts.paid()&&!hasPending(tx)) {
                try {
                    var app=catalog.application(new WorkflowStartBoundary.Request(text(w,"businessReference"),expected.customerId(),amount,uuid(w,"payoutAccountId")));
                    if(app.source().reviewedSafe()) {
                        try {VirtualGrantWorkflowControl.requireContinuationClear(tx,expected,app.source().documentId(),app.source().documentVersion(),agents);canResume=true;}
                        catch(SimulationFailure hold){if(hold.status()!=400)throw hold;}
                    }
                } catch(SimulationFailure missingCandidate) {if(missingCandidate.status()!=400)throw missingCandidate;}
            }
            var out=new LinkedHashMap<String,Object>();for(var key:PUBLIC_FIELDS)out.put(key,w.get(key));
            out.put("riskLimit",limit);if("PAID".equals(w.get("state")))out.put("historicalApprovedRiskLimit",historical);
            out.put("activeJob",job);out.put("activeQuarantines",active);
            // No selected-evidence projection is available from opaque stored agent frames.
            out.put("canApprove",false);out.put("canResume",canResume);out.put("resumeCapability","TYPED_READINESS_ONLY");out.put("executionMode",VirtualTransactionalStore.MODE);
            return CanonicalJson.immutableObject(out);
        }catch(RuntimeException unconfirmed){throw bad();}
    }

    private static Map<UUID,VirtualGrantTransactionJournal.TypedReference> references(TransactionalStore.Tx tx,Scope scope) {
        var out=new LinkedHashMap<UUID,VirtualGrantTransactionJournal.TypedReference>();var resultIds=new HashSet<UUID>();
        for(var r:VirtualGrantTransactionJournal.typedReferences(tx))if(r.workflowId().equals(scope.workflowId())) {
            if(!r.customerId().equals(scope.customerId())||r.generation()>scope.generation()||out.put(r.targetRunId(),r)!=null
                    ||r.resultId()!=null&&!resultIds.add(r.resultId()))throw bad();
            var own=VirtualGrantGenerationHistory.validate(tx,new Scope(r.workflowId(),r.generation(),r.customerId()));
            var root=tx.get("virtual_grant_profile_root_material",own.rootGrantId().toString());
            var stageMap=map(map(root.get("workflowPlan")).get("stageAgents"));
            var g=tx.get(GRANTS,r.grantId().toString());
            if(g==null||!g.keySet().equals(Set.of("grantId","actionId","targetRunId","workflowId","generation","customerId","action","state")))throw bad();
            requireScope(g,new Scope(r.workflowId(),r.generation(),r.customerId()));
            if(!r.grantId().equals(uuid(g,"grantId"))||!r.actionId().equals(uuid(g,"actionId"))||!r.targetRunId().equals(uuid(g,"targetRunId")))throw bad();
            var action=AllowedAction.valueOf(text(g,"action"));var agent=map(stageMap.get(action.name()));
            if(!agent.keySet().equals(Set.of("agentId","agentVersion"))||!r.agentId().equals(agent.get("agentId"))
                    ||r.agentVersion()!=positive(agent,"agentVersion")||!r.documentId().equals(own.sourceDocId())||r.documentVersion()!=own.sourceVersion())throw bad();
            if(!Set.of("ISSUED","CONSUMED").contains(g.get("state"))
                    ||("CONSUMED".equals(g.get("state")))!=(r.resultId()!=null))throw bad();
        }
        for(var r:out.values())if(r.sourceRunId()!=null) {
            var parent=out.get(r.sourceRunId());
            if(parent==null||parent.generation()!=r.generation()||parent.resultId()==null||!parent.resultId().equals(r.sourceResultId()))throw bad();
        } else if(r.sourceResultId()!=null)throw bad();
        for(var r:out.values()) {
            var seen=new HashSet<UUID>();var node=r;
            while(node!=null) {if(!seen.add(node.targetRunId()))throw bad();node=node.sourceRunId()==null?null:out.get(node.sourceRunId());}
        }
        for(var e:tx.rows(GRANTS).entrySet())if(scope.workflowId().toString().equals(e.getValue().get("workflowId"))) {
            var r=out.get(uuid(e.getValue(),"targetRunId"));if(r==null||!e.getKey().equals(r.grantId().toString()))throw bad();
        }
        return out;
    }
    private record Counts(int used,int reserved,int runs,boolean paid) { }
    private static Counts counts(TransactionalStore.Tx tx,Scope scope,SimulationSpec.RiskTerms terms,
                                  Map<UUID,VirtualGrantTransactionJournal.TypedReference> refs) {
        int charges=0,runs=0,reserved=0,consumed=0;var stages=new HashSet<String>();var ordinals=new HashSet<Integer>();
        for(var e:tx.rows(PREPARATIONS).entrySet()) {
            var marker=VirtualGrantEvaluationAccounting.decodeMarker(e.getValue());if(!scope.workflowId().equals(marker.identity().workflowId()))continue;
            var i=marker.identity();own(tx,scope,new Scope(i.workflowId(),i.generation(),i.customerId()),terms);
            if(!e.getKey().equals(i.targetRunId().toString())||!refs.containsKey(i.targetRunId())||!ordinals.add(marker.kycRunsAfter()))throw bad();
            VirtualGrantTransactionJournal.requireAccountingPreparation(tx,marker,null);
            var input=tx.get("virtual_grant_profile_kyc_inputs",i.targetRunId().toString());
            if(input==null||!input.keySet().equals(Set.of("canonicalInput","inputSnapshotHash"))
                    ||!(input.get("canonicalInput") instanceof Map<?,?>)||!marker.inputSnapshotHash().equals(input.get("inputSnapshotHash")))throw bad();
            if(marker.chargedPoints()!=(marker.kycRunsAfter()==1?terms.kycPoints():0))throw bad();
            runs=Math.addExact(runs,1);
        }
        for(int i=1;i<=runs;i++)if(!ordinals.contains(i))throw bad();
        for(var e:tx.rows(CHARGES).entrySet()) {
            var r=e.getValue();if(!scope.workflowId().toString().equals(r.get("workflowId")))continue;
            if(!r.keySet().equals(Set.of("workflowId","generation","customerId","stage","points","phaseRequestId","grantId","actionId","targetRunId","resultId")))throw bad();
            own(tx,scope,scope(r),terms);String stage=text(r,"stage");if(!stages.add(stage)||!e.getKey().equals(scope.workflowId()+":"+stage))throw bad();
            var ref=refs.get(uuid(r,"targetRunId"));if(ref==null||!ref.grantId().equals(uuid(r,"grantId"))||!ref.actionId().equals(uuid(r,"actionId"))
                    ||!new Scope(ref.workflowId(),ref.generation(),ref.customerId()).equals(scope(r)))throw bad();
            int points=nonnegative(r,"points");
            if("KYC".equals(stage)) {
                if(points!=terms.kycPoints()||r.get("resultId")!=null)throw bad();
                var marker=VirtualGrantEvaluationAccounting.decodeMarker(tx.get(PREPARATIONS,ref.targetRunId().toString()));
                if(marker.kycRunsAfter()!=1||marker.chargedPoints()!=points||!marker.identity().globalRequestId().equals(uuid(r,"phaseRequestId"))
                        ||!new Scope(marker.identity().workflowId(),marker.identity().generation(),marker.identity().customerId()).equals(scope(r))
                        ||!marker.identity().grantId().equals(ref.grantId())||!marker.identity().actionId().equals(ref.actionId())
                        ||!marker.identity().targetRunId().equals(ref.targetRunId()))throw bad();
            } else if("LOAN".equals(stage)) {
                if(points!=terms.loanPoints())throw bad();var meta=VirtualGrantTransactionJournal.readResultMetadata(tx,
                    new Scope(ref.workflowId(),ref.generation(),ref.customerId()),uuid(r,"resultId"),AllowedAction.CREATE_LOAN_RECOMMENDATION);
                if(!meta.identity().globalRequestId().equals(uuid(r,"phaseRequestId"))||!meta.reference().equals(ref))throw bad();
            } else throw bad();charges=Math.addExact(charges,points);
        }
        if(stages.contains("KYC")!=(runs>0)||runs>terms.maxAutomaticKycRuns())throw bad();
        for(var e:tx.rows(RISK).entrySet()) {
            var r=e.getValue();if(!scope.workflowId().toString().equals(r.get("workflowId")))continue;
            if(!r.keySet().equals(Set.of("reservationId","paymentId","approvalId","grantId","actionId","targetRunId","workflowId","generation","customerId","policyVersion","points","state")))throw bad();
            own(tx,scope,scope(r),terms);var d=VirtualGrantTransactionJournal.readPlanMetadata(tx,uuid(r,"reservationId"));
            if(!new Scope(d.workflowId(),d.generation(),d.customerId()).equals(scope(r))
                    ||!e.getKey().equals(d.reservationId().toString())||!d.paymentId().equals(uuid(r,"paymentId"))||!d.approvalId().equals(uuid(r,"approvalId"))
                    ||!d.grantId().equals(uuid(r,"grantId"))||!d.actionId().equals(uuid(r,"actionId"))||!d.targetRunId().equals(uuid(r,"targetRunId"))
                    ||!terms.policyVersion().equals(r.get("policyVersion"))||nonnegative(r,"points")!=terms.payPoints())throw bad();
            if("RESERVED".equals(r.get("state"))&&d.reservationState()==ReservationState.RESERVED)reserved=Math.addExact(reserved,terms.payPoints());
            else if("CONSUMED".equals(r.get("state"))&&d.reservationState()==ReservationState.COMMITTED)consumed=Math.addExact(consumed,terms.payPoints());
            else throw bad();
        }
        for(var ref:refs.values()) {
            var grant=tx.get(GRANTS,ref.grantId().toString());if(!"CONSUMED".equals(grant.get("state")))continue;
            var action=AllowedAction.valueOf(text(grant,"action"));
            VirtualGrantTransactionJournal.readResultMetadata(tx,new Scope(ref.workflowId(),ref.generation(),ref.customerId()),ref.resultId(),action);
            if(action==AllowedAction.EVALUATE_KYC&&!tx.rows(PREPARATIONS).containsKey(ref.targetRunId().toString()))throw bad();
            if(action==AllowedAction.CREATE_LOAN_RECOMMENDATION&&!stages.contains("LOAN"))throw bad();
        }
        for(var e:tx.rows("virtual_grant_profile_payment_plans").entrySet())if(scope.workflowId().toString().equals(e.getValue().get("workflowId"))) {
            if(tx.get(RISK,e.getKey())==null)throw bad();
        }
        int used=Math.addExact(charges,consumed);
        for(var r:tx.rows(PREPARATIONS).values()) {
            var marker=VirtualGrantEvaluationAccounting.decodeMarker(r);
            if(marker.identity().workflowId().equals(scope.workflowId())&&marker.usedRiskAfter()>used)throw bad();
        }
        return new Counts(used,reserved,runs,consumed>0);
    }
    private static void own(TransactionalStore.Tx tx,Scope current,Scope old,SimulationSpec.RiskTerms terms) {
        if(!current.workflowId().equals(old.workflowId())||!current.customerId().equals(old.customerId())||old.generation()>current.generation()
                ||!VirtualGrantGenerationHistory.validate(tx,old).terms().equals(terms))throw bad();
    }
    private static VirtualGrantTransactionJournal.ReadResultMetadata currentResult(TransactionalStore.Tx tx,Map<String,Object>w,Scope scope,String key,AllowedAction action) {
        return w.get(key)==null?null:VirtualGrantTransactionJournal.readResultMetadata(tx,scope,uuid(w,key),action);
    }
    private static void validateApproval(TransactionalStore.Tx tx,ApprovalSnapshot a,Scope current,SimulationSpec.RiskTerms terms,
                                         Map<UUID,VirtualGrantTransactionJournal.TypedReference> refs) {
        own(tx,current,a.material().scope(),terms);var m=a.material();
        var k=VirtualGrantTransactionJournal.readResultMetadata(tx,m.scope(),m.kycResultId(),AllowedAction.EVALUATE_KYC);
        var l=VirtualGrantTransactionJournal.readResultMetadata(tx,m.scope(),m.loanResultId(),AllowedAction.CREATE_LOAN_RECOMMENDATION);
        int extra=a.decision()==ReviewDecision.APPROVE?terms.additionalApprovalLimit():0;
        if(k.conclusion()!=com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.BusinessConclusion.POSITIVE
                ||l.conclusion()!=com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.BusinessConclusion.POSITIVE
                ||!k.reference().targetRunId().equals(l.reference().sourceRunId())||!m.kycResultId().equals(l.reference().sourceResultId())
                ||!m.documentId().equals(l.reference().documentId())||m.documentVersion()!=l.reference().documentVersion()
                ||!m.policyVersion().equals(terms.policyVersion())||a.extraRiskLimit()!=extra
                ||a.riskLimit()!=Math.addExact(terms.baseLimit(),extra))throw bad();
    }
    private static boolean invalidated(TransactionalStore.Tx tx,String table,UUID id,String key,Map<String,Object> original) {
        var tomb=tx.get(table,id.toString());if(tomb==null)return false;
        if(!tomb.keySet().equals(Set.of(key,"quarantineId"))||!original.equals(tomb.get(key)))throw bad();uuid(tomb,"quarantineId");return true;
    }
    private static Map<String,Object> job(TransactionalStore.Tx tx,Map<String,Object>w,Scope scope) {
        if(w.get("activeJobId")==null)return null;var j=tx.get("virtual_jobs",uuid(w,"activeJobId").toString());
        if(j==null||!j.keySet().equals(Set.of("jobId","workflowId","generation","phase","state","runId","approvalId")))throw bad();
        if(!uuid(w,"activeJobId").equals(uuid(j,"jobId"))||!scope.workflowId().equals(uuid(j,"workflowId"))||positive(j,"generation")!=scope.generation())throw bad();
        if(!Set.of("KYC","LOAN","PAYMENT").contains(j.get("phase"))||!Set.of("PENDING","RUNNING","SUCCEEDED","FAILED","CANCELLED").contains(j.get("state")))throw bad();
        if(j.get("runId")!=null)uuid(j,"runId");if(j.get("approvalId")!=null)uuid(j,"approvalId");return CanonicalJson.immutableObject(j);
    }
    private static Map<AllowedAction,SyntheticRootProvisionBinding.AgentReference> agents(Map<String,Object>w) {
        var out=new EnumMap<AllowedAction,SyntheticRootProvisionBinding.AgentReference>(AllowedAction.class);
        for(var e:map(w.get("typedStageAgents")).entrySet()) {var a=map(e.getValue());if(!a.keySet().equals(Set.of("agentId","agentVersion")))throw bad();
            out.put(AllowedAction.valueOf(e.getKey()),new SyntheticRootProvisionBinding.AgentReference(text(a,"agentId"),positive(a,"agentVersion")));}
        if(!out.containsKey(AllowedAction.EVALUATE_KYC))throw bad();return Map.copyOf(out);
    }
    private static VirtualQuarantineService.Target target(Map<String,Object>hold) {
        return new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.valueOf(text(hold,"scope")),map(hold.get("target")));
    }
    private static boolean matches(VirtualQuarantineService.Target t,Scope scope,Map<String,Object>w,
            Map<AllowedAction,SyntheticRootProvisionBinding.AgentReference> agents,List<VirtualGrantTransactionJournal.TypedReference> current,
            Map<UUID,VirtualGrantTransactionJournal.TypedReference> all) {
        if(t.scope()==VirtualQuarantineService.Scope.WORKFLOW)return scope.workflowId().toString().equals(t.fields().get("workflowId"));
        if(t.scope()==VirtualQuarantineService.Scope.SOURCE_VERSION&&w.get("documentId").equals(t.fields().get("documentId"))&&w.get("documentVersion").equals(t.fields().get("documentVersion")))return true;
        if(t.scope()==VirtualQuarantineService.Scope.AGENT_VERSION&&agents.values().stream().anyMatch(a->a.agentId().equals(t.fields().get("agentId"))&&Integer.valueOf(a.version()).equals(t.fields().get("agentVersion"))))return true;
        var affected=new HashSet<UUID>();
        for(var r:all.values()) {
            boolean match=switch(t.scope()) {
                case RUN->r.targetRunId().toString().equals(t.fields().get("runId"));
                case RESULT->r.resultId()!=null&&r.resultId().toString().equals(t.fields().get("resultId"));
                case SOURCE_VERSION->r.documentId().toString().equals(t.fields().get("documentId"))&&Integer.valueOf(r.documentVersion()).equals(t.fields().get("documentVersion"));
                case AGENT_VERSION->r.agentId().equals(t.fields().get("agentId"))&&Integer.valueOf(r.agentVersion()).equals(t.fields().get("agentVersion"));
                default->false;
            };if(match)affected.add(r.targetRunId());
        }
        boolean changed;do {changed=false;for(var r:all.values())if(r.sourceRunId()!=null&&affected.contains(r.sourceRunId()))changed|=affected.add(r.targetRunId());}while(changed);
        return current.stream().anyMatch(r->affected.contains(r.targetRunId()));
    }
    private static boolean hasPending(TransactionalStore.Tx tx) {
        if(tx instanceof ActionJournal.ReservedTx owned)return !owned.pendingIdentities().isEmpty();
        boolean pending=false;
        for(var e:tx.rows(ActionJournal.TABLE).entrySet()) {
            var row=e.getValue();boolean reserved="RESERVED".equals(row.get("reservationStatus"));
            var keys=reserved?Set.of("actorId","requestId","operation","canonicalBodyHash","persistenceMode","durable","reservationStatus","attemptToken")
                    :Set.of("actorId","requestId","operation","canonicalBodyHash","persistenceMode","durable","reply");
            if(!row.keySet().equals(keys)||!e.getKey().equals(uuid(row,"requestId").toString())
                    ||!VirtualTransactionalStore.MODE.equals(row.get("persistenceMode"))||!Boolean.FALSE.equals(row.get("durable"))
                    ||!text(row,"canonicalBodyHash").matches("[0-9a-f]{64}"))throw bad();
            text(row,"actorId");text(row,"operation");
            if(reserved){uuid(row,"attemptToken");pending=true;}
            else {var reply=map(row.get("reply"));if(!e.getKey().equals(reply.get("requestId"))||!(reply.get("replayed")instanceof Boolean))throw bad();}
        }
        return pending;
    }
    private static Map<String,Object> workflow(TransactionalStore.Tx tx,Scope scope) {
        if(tx==null||scope==null)throw bad();var w=tx.get(WORKFLOWS,scope.workflowId().toString());if(w==null)throw bad();requireScope(w,scope);return w;
    }
    private static Scope scope(Map<String,Object>r){return new Scope(uuid(r,"workflowId"),positive(r,"generation"),text(r,"customerId"));}
    private static void requireScope(Map<String,Object>r,Scope s){if(!s.equals(scope(r)))throw bad();}
    private static String text(Map<String,Object>r,String k){if(!(r.get(k)instanceof String s)||s.isBlank())throw bad();return s;}
    private static UUID uuid(Map<String,Object>r,String k){return uuidFrom(r.get(k));}
    private static UUID uuidFrom(Object v){if(!(v instanceof String s))throw bad();UUID id=UUID.fromString(s);if(!id.toString().equals(s))throw bad();return id;}
    private static int nonnegative(Map<String,Object>r,String k){if(!(r.get(k)instanceof Integer n)||n<0)throw bad();return n;}
    private static int positive(Map<String,Object>r,String k){int n=nonnegative(r,k);if(n<1)throw bad();return n;}
    private static List<?> list(Object v){if(!(v instanceof List<?> l))throw bad();return l;}
    @SuppressWarnings("unchecked") private static Map<String,Object> map(Object v){if(!(v instanceof Map<?,?>m))throw bad();for(var k:m.keySet())if(!(k instanceof String))throw bad();return(Map<String,Object>)m;}
    private static SimulationFailure bad(){return SimulationFailure.unavailable();}
}
