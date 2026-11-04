package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticMockPaymentReceiptCodec;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import com.finsec.fuse.reimplementation.simulation.SimulationFailure;
import com.finsec.fuse.reimplementation.simulation.SimulationSpec;
import com.finsec.fuse.reimplementation.simulation.VirtualQuarantineService;
import com.finsec.fuse.reimplementation.simulation.VirtualWorkflowLane.Scope;
import java.time.Instant;
import java.util.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBinding.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentTransactionBinding.*;

/** Authorized workflow trace metadata only; identity order is not execution-time chronology. */
public final class TypedWorkflowTraceProjection {
    private TypedWorkflowTraceProjection() { }
    private static final String GRANTS="virtual_grant_profile_grants", RESULTS="virtual_grant_profile_results",
            PLAN_RECEIPTS="virtual_grant_profile_plan_receipts", APPROVALS="virtual_grant_profile_review_approvals",
            PLANS="virtual_grant_profile_payment_plans", PAYMENTS="virtual_grant_profile_payments",
            CHARGES="virtual_grant_profile_stage_charges", PREPARATIONS="virtual_grant_profile_kyc_preparations";

    /** READ and customer authorization must precede this call, exactly as for project. */
    public static boolean applies(TransactionalStore.Tx tx, Scope expected) {
        return TypedWorkflowReadProjection.applies(tx,expected);
    }

    /** Borrowed ordinary READ transaction. No business body, opaque frame or authority is projected. */
    public static Map<String,Object> project(TransactionalStore.Tx tx, Scope expected,
                                             SimulationSpec.Catalog catalog, Instant now) {
        try {
            TypedWorkflowReadProjection.project(tx,expected,catalog,now);
            var grants=new Rows("grantId");var results=new Rows("resultId");var dependencies=new Rows("childRunId");
            var approvals=new Rows("approvalId");var risk=new Rows("riskEventId",true);var payments=new Rows("paymentId");
            var audits=new Rows("auditEventId",true);var sources=new Rows("runId");
            var refs=new LinkedHashMap<UUID,VirtualGrantTransactionJournal.TypedReference>();
            for(var ref:VirtualGrantTransactionJournal.typedReferences(tx))if(ref.workflowId().equals(expected.workflowId())) {
                own(tx,expected,new Scope(ref.workflowId(),ref.generation(),ref.customerId()));
                if(refs.put(ref.targetRunId(),ref)!=null)throw bad();
            }
            for(var ref:refs.values()) {
                var scope=new Scope(ref.workflowId(),ref.generation(),ref.customerId());var g=map(tx.get(GRANTS,ref.grantId().toString()));
                var action=AllowedAction.valueOf(text(g,"action"));var state=GrantState.valueOf(text(g,"state"));
                grants.add(row("grantId",ref.grantId().toString(),"actionId",ref.actionId().toString(),"targetRunId",ref.targetRunId().toString(),
                        "workflowId",ref.workflowId().toString(),"generation",ref.generation(),"action",action.name(),"state",state.name(),"status",state.name()));
                var origin=VirtualGrantTransactionJournal.generationOrigin(tx,scope,
                        VirtualGrantGenerationHistory.validate(tx,scope).rootGrantId(),VirtualGrantGenerationHistory.validate(tx,scope).rootRequestId());
                if(!origin.documentId().equals(ref.documentId())||origin.documentVersion()!=ref.documentVersion())throw bad();
                sources.add(row("runId",ref.targetRunId().toString(),"documentId",ref.documentId().toString(),
                        "documentVersion",ref.documentVersion(),"contentHash",origin.contentHash()),ref.generation());
                if(ref.sourceRunId()!=null) {
                    var parent=refs.get(ref.sourceRunId());
                    if(parent==null||parent.resultId()==null||!parent.resultId().equals(ref.sourceResultId())
                            ||parent.generation()!=ref.generation())throw bad();
                    var pg=map(tx.get(GRANTS,parent.grantId().toString()));
                    var parentMeta=VirtualGrantTransactionJournal.readResultMetadata(tx,scope,parent.resultId(),AllowedAction.valueOf(text(pg,"action")));
                    if(parentMeta.conclusion()!=com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.BusinessConclusion.POSITIVE)throw bad();
                    issuance(tx,parent,ref);
                    dependencies.add(row("parentRunId",parent.targetRunId().toString(),"childRunId",ref.targetRunId().toString(),
                            "parentResultId",parent.resultId().toString(),"generation",ref.generation()));
                }
                if(ref.resultId()==null)continue;
                var meta=VirtualGrantTransactionJournal.readResultMetadata(tx,scope,ref.resultId(),action);
                if(!meta.reference().equals(ref)||state!=GrantState.CONSUMED)throw bad();
                var material=map(tx.get(RESULTS,ref.resultId().toString()));var digest=resultDigest(tx,meta,material);
                results.add(row("resultId",ref.resultId().toString(),"runId",ref.targetRunId().toString(),"workflowId",ref.workflowId().toString(),
                        "generation",ref.generation(),"bindingProfile",text(material,"bindingProfile"),"bindingDigest",digest));
            }
            for(var e:tx.rows(APPROVALS).entrySet()) {
                var raw=e.getValue();var material=map(raw.get("material"));var scope=scope(map(material.get("scope")));
                if(!scope.workflowId().equals(expected.workflowId()))continue;own(tx,expected,scope);
                var a=VirtualGrantTransactionJournal.readApprovalMetadata(tx,canonical(e.getKey()));
                approvals.add(row("approvalId",a.approvalId().toString(),"reviewRequestId",a.reviewRequestId().toString(),"workflowId",scope.workflowId().toString(),
                        "generation",scope.generation(),"decision",a.decision().name(),"state",a.state().name(),"status",a.state().name(),
                        "createdAt",a.createdAt().toString(),"expiresAt",a.expiresAt().toString(),"reviewSnapshotHash",a.reviewSnapshotHash()));
                // The actual immutable Review record supplies this creation time; not a read-time event.
                audits.add(row("auditEventId",a.reviewRequestId().toString(),"workflowId",scope.workflowId().toString(),
                        "eventType",a.decision()==ReviewDecision.APPROVE?"APPROVAL_RECORDED":"REJECTION_RECORDED","createdAt",a.createdAt().toString()),scope.generation());
            }
            for(var e:tx.rows(CHARGES).entrySet()) {
                var r=e.getValue();if(!expected.workflowId().toString().equals(r.get("workflowId")))continue;
                var scope=scope(r);own(tx,expected,scope);var stage=text(r,"stage");
                if(!Set.of("KYC","LOAN").contains(stage)||!e.getKey().equals(scope.workflowId()+":"+stage))throw bad();
                var ref=refs.get(uuid(r,"targetRunId"));if(ref==null||ref.generation()!=scope.generation())throw bad();
                if("KYC".equals(stage)) {
                    var marker=VirtualGrantEvaluationAccounting.decodeMarker(tx.get(PREPARATIONS,ref.targetRunId().toString()));
                    VirtualGrantTransactionJournal.requireAccountingPreparation(tx,marker,null);
                    if(!marker.identity().globalRequestId().equals(uuid(r,"phaseRequestId")))throw bad();
                } else {
                    var meta=VirtualGrantTransactionJournal.readResultMetadata(tx,scope,uuid(r,"resultId"),AllowedAction.CREATE_LOAN_RECOMMENDATION);
                    if(!meta.identity().globalRequestId().equals(uuid(r,"phaseRequestId")))throw bad();
                }
                var terms=VirtualGrantGenerationHistory.validate(tx,scope).terms();int points=nonnegative(r,"points");
                if(points!=("KYC".equals(stage)?terms.kycPoints():terms.loanPoints()))throw bad();
                risk.add(row("riskEventId",e.getKey(),"workflowId",scope.workflowId().toString(),"generation",scope.generation(),
                        "eventType","CHARGE","stage",stage,"points",points,"runId",ref.targetRunId().toString(),"policyVersion",terms.policyVersion()));
            }
            for(var e:tx.rows(PLANS).entrySet()) {
                var r=e.getValue();if(!expected.workflowId().toString().equals(r.get("workflowId")))continue;
                var d=VirtualGrantTransactionJournal.readPlanMetadata(tx,canonical(e.getKey()));var scope=new Scope(d.workflowId(),d.generation(),d.customerId());
                own(tx,expected,scope);var reserve=reserveRecord(tx,d);var identity=map(reserve.get("identity"));
                var reserveRequest=uuid(identity,"globalRequestId");int points=nonnegative(reserve,"riskPoints");
                var terms=VirtualGrantGenerationHistory.validate(tx,scope).terms();if(points!=terms.payPoints())throw bad();
                risk.add(row("riskEventId",reserveRequest.toString(),"workflowId",scope.workflowId().toString(),"generation",scope.generation(),
                        "eventType","RESERVE","stage","PAYMENT","points",points,"runId",d.targetRunId().toString(),"policyVersion",terms.policyVersion()));
                if(d.reservationState()!=ReservationState.COMMITTED)continue;
                var meta=VirtualGrantTransactionJournal.readResultMetadata(tx,scope,d.paymentId(),AllowedAction.EXECUTE_MOCK_PAYMENT);
                var payment=map(tx.get(PAYMENTS,d.paymentId().toString()));var storedResult=map(tx.get(RESULTS,d.paymentId().toString()));
                var digest=resultDigest(tx,meta,storedResult);
                if(!digest.equals(text(payment,"receiptDigest"))||digest.length()!=64
                        ||!SyntheticMockPaymentReceiptCodec.PROFILE_NAME.equals(payment.get("profileName"))
                        ||!Integer.valueOf(SyntheticMockPaymentReceiptCodec.PROFILE_VERSION).equals(payment.get("profileVersion")))throw bad();
                payments.add(row("paymentId",d.paymentId().toString(),"approvalId",d.approvalId().toString(),"reservationId",d.reservationId().toString(),
                        "grantId",d.grantId().toString(),"runId",d.targetRunId().toString(),"workflowId",scope.workflowId().toString(),"generation",scope.generation(),
                        "amountKrw",d.amountKrw(),"reservationState",d.reservationState().name(),"approvalState",d.approvalState().name(),
                        "profileName",payment.get("profileName"),"profileVersion",payment.get("profileVersion"),"receiptDigest",digest));
                risk.add(row("riskEventId",meta.identity().globalRequestId().toString(),"workflowId",scope.workflowId().toString(),"generation",scope.generation(),
                        "eventType","CONSUME","stage","PAYMENT","points",points,"runId",d.targetRunId().toString(),"policyVersion",terms.policyVersion()));
            }
            for(var e:tx.rows(PAYMENTS).entrySet()) {
                var input=map(e.getValue().get("input"));if(!expected.workflowId().toString().equals(input.get("workflowId")))continue;
                if(!e.getKey().equals(uuid(input,"paymentId").toString()))throw bad();
                var d=VirtualGrantTransactionJournal.readPlanMetadata(tx,uuid(input,"reservationId"));
                if(!d.workflowId().equals(expected.workflowId())||d.reservationState()!=ReservationState.COMMITTED
                        ||!d.paymentId().toString().equals(e.getKey()))throw bad();
            }
            legacyAudit(tx,expected,refs.values(),audits);
            var out=row("workflowId",expected.workflowId().toString(),"generation",expected.generation(),"runs",List.of(),"results",results.values(),
                    "grants",grants.values(),"dependencies",dependencies.values(),"approvals",approvals.values(),"riskEvents",risk.values(),
                    "payments",payments.values(),"auditEvents",audits.values(),"sourceUses",sources.values(),
                    "executionMode",VirtualTransactionalStore.MODE,"cryptographicAuthorityImplemented",false);
            return CanonicalJson.immutableObject(out);
        }catch(RuntimeException unconfirmed){throw bad();}
    }

    private static void issuance(TransactionalStore.Tx tx,VirtualGrantTransactionJournal.TypedReference parent,
                                 VirtualGrantTransactionJournal.TypedReference child) {
        var link=map(tx.get("virtual_grant_profile_successors",parent.grantId().toString()));
        if(!link.keySet().equals(Set.of("childGrantId"))||!child.grantId().toString().equals(link.get("childGrantId")))throw bad();
        Map<String,Object> found=null;
        for(var e:tx.rows("virtual_grant_profile_receipts").entrySet()) {
            var r=e.getValue();if(!"ISSUANCE".equals(r.get("kind")))continue;var i=map(r.get("identity"));
            if(!child.grantId().toString().equals(i.get("grantId")))continue;
            if(found!=null||!r.keySet().equals(Set.of("identity","kind","result","parentGrantId"))||r.get("result")!=null
                    ||!parent.grantId().toString().equals(r.get("parentGrantId")))throw bad();found=r;
            if(!i.keySet().equals(Set.of("actorId","globalRequestId","operation","canonicalizationVersion","canonicalBodyDigest",
                    "grantId","actionId","targetRunId","workflowId","generation","customerId")))throw bad();
            var id=new com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity(text(i,"actorId"),uuid(i,"globalRequestId"),
                    text(i,"operation"),text(i,"canonicalizationVersion"),text(i,"canonicalBodyDigest"),uuid(i,"grantId"),uuid(i,"actionId"),
                    uuid(i,"targetRunId"),uuid(i,"workflowId"),positive(i,"generation"),text(i,"customerId"));
            if(!e.getKey().equals(id.globalRequestId().toString())||!id.workflowId().equals(child.workflowId())||id.generation()!=child.generation()
                    ||!id.customerId().equals(child.customerId())||!id.actionId().equals(child.actionId())||!id.targetRunId().equals(child.targetRunId()))throw bad();
            var g=completed(tx,id.globalRequestId());var reply=new LinkedHashMap<String,Object>(map(g.get("reply")));
            if(!id.actorId().equals(g.get("actorId"))||!id.operation().equals(g.get("operation"))
                    ||!CanonicalJson.sha256(i).equals(g.get("canonicalBodyHash"))||!e.getKey().equals(reply.remove("requestId"))
                    ||!(reply.remove("replayed")instanceof Boolean)||!r.equals(reply))throw bad();
        }
        if(found==null)throw bad();
    }

    private static String resultDigest(TransactionalStore.Tx tx,VirtualGrantTransactionJournal.ReadResultMetadata meta,Map<String,Object> stored) {
        var request=meta.identity().globalRequestId();var local=map(tx.get("virtual_grant_profile_receipts",request.toString()));
        var global=completed(tx,request);var reply=map(global.get("reply"));
        var digest=text(stored,"bindingDigest");
        if(digest.isEmpty()||digest.length()%2!=0||!digest.matches("[0-9a-f]+")
                ||!digest.equals(map(local.get("result")).get("bindingDigest"))
                ||!digest.equals(map(reply.get("result")).get("bindingDigest")))throw bad();
        return digest;
    }
    private static Map<String,Object> reserveRecord(TransactionalStore.Tx tx,PaymentDomain d) {
        Map<String,Object> found=null;
        for(var e:tx.rows(PLAN_RECEIPTS).entrySet()) {
            var r=e.getValue();if(!"RESERVE".equals(r.get("purpose")))continue;var domain=map(r.get("domain"));
            if(!d.reservationId().toString().equals(domain.get("reservationId")))continue;
            if(found!=null)throw bad();found=r;var i=map(r.get("identity"));
            if(!e.getKey().equals(uuid(i,"globalRequestId").toString()))throw bad();
            var global=completed(tx,uuid(i,"globalRequestId"));var reply=new LinkedHashMap<String,Object>(map(global.get("reply")));
            if(!e.getKey().equals(reply.remove("requestId"))||!(reply.remove("replayed") instanceof Boolean)||!r.equals(reply))throw bad();
        }
        if(found==null)throw bad();return found;
    }
    private static void legacyAudit(TransactionalStore.Tx tx,Scope requested,
                                    Collection<VirtualGrantTransactionJournal.TypedReference> refs,Rows out) {
        for(var e:tx.rows("virtual_audit").entrySet()) {
            var r=e.getValue();if(!requested.workflowId().toString().equals(r.get("workflowId")))continue;
            if(!r.keySet().equals(Set.of("auditEventId","workflowId","actionId","eventType","createdAt"))
                    ||!e.getKey().equals(uuid(r,"auditEventId").toString()))throw bad();
            var kind=text(r,"eventType");if(!Set.of("QUARANTINE_ACTIVE","REMEDIATION_RECORDED").contains(kind))continue;
            var global=completed(tx,uuid(r,"actionId"));var operation=text(global,"operation");var reply=map(global.get("reply"));
            if(!operation.equals("QUARANTINE_ACTIVE".equals(kind)?"SIM_QUARANTINE":"SIM_RELEASE_QUARANTINE"))throw bad();
            var q=map(tx.get("virtual_quarantines",uuid(reply,"quarantineId").toString()));
            var target=new VirtualQuarantineService.Target(VirtualQuarantineService.Scope.valueOf(text(q,"scope")),map(q.get("target")));
            if(!q.get("quarantineId").equals(reply.get("quarantineId"))||!target.scope().name().equals(reply.get("scope"))
                    ||!target.fields().equals(reply.get("target"))||!"ALLOW".equals(reply.get("decision"))
                    ||!("QUARANTINE_ACTIVE".equals(kind)?"ACTIVE":"RELEASED").equals(reply.get("state")))throw bad();
            if(!belongs(tx,requested,refs,target))throw bad();
            var at=text(r,"createdAt");if(!Instant.parse(at).toString().equals(at))throw bad();
            out.add(row("auditEventId",e.getKey(),"workflowId",requested.workflowId().toString(),"actionId",r.get("actionId"),
                    "eventType",kind,"createdAt",at));
        }
    }
    private static boolean belongs(TransactionalStore.Tx tx,Scope requested,
                                   Collection<VirtualGrantTransactionJournal.TypedReference> refs,VirtualQuarantineService.Target target) {
        var fields=target.fields();
        if(target.scope()==VirtualQuarantineService.Scope.WORKFLOW)
            return requested.workflowId().toString().equals(fields.get("workflowId"));
        if(target.scope()==VirtualQuarantineService.Scope.SOURCE_VERSION) {
            var current=map(tx.get("virtual_workflows",requested.workflowId().toString()));
            if(current.get("documentId").equals(fields.get("documentId"))&&current.get("documentVersion").equals(fields.get("documentVersion")))return true;
        }
        var roots=new HashSet<UUID>();
        for(var ref:refs) {
            own(tx,requested,new Scope(ref.workflowId(),ref.generation(),ref.customerId()));
            boolean found=switch(target.scope()) {
                case RUN->ref.targetRunId().toString().equals(fields.get("runId"));
                case RESULT->ref.resultId()!=null&&ref.resultId().toString().equals(fields.get("resultId"));
                case SOURCE_VERSION->ref.documentId().toString().equals(fields.get("documentId"))&&Integer.valueOf(ref.documentVersion()).equals(fields.get("documentVersion"));
                case AGENT_VERSION->ref.agentId().equals(fields.get("agentId"))&&Integer.valueOf(ref.agentVersion()).equals(fields.get("agentVersion"));
                default->false;
            };
            if(found)return true;
            if(target.scope()==VirtualQuarantineService.Scope.AGENT_VERSION) {
                var history=VirtualGrantGenerationHistory.validate(tx,new Scope(ref.workflowId(),ref.generation(),ref.customerId()));
                if(!roots.add(history.rootGrantId()))continue;
                var origin=map(tx.get("virtual_grant_profile_root_material",history.rootGrantId().toString()));
                var declared=map(map(origin.get("workflowPlan")).get("stageAgents"));
                for(var e:declared.entrySet()) {
                    AllowedAction.valueOf(e.getKey());var agent=map(e.getValue());
                    if(!agent.keySet().equals(Set.of("agentId","agentVersion")))throw bad();
                    if(text(agent,"agentId").equals(fields.get("agentId"))&&Integer.valueOf(positive(agent,"agentVersion")).equals(fields.get("agentVersion")))return true;
                }
            }
        }
        return false;
    }

    private static Map<String,Object> completed(TransactionalStore.Tx tx,UUID request) {
        // Trace consumes a normal already-authorized READ Tx, never bypasses an owned facade's journal-table guard.
        var r=map(tx.get(ActionJournal.TABLE,request.toString()));
        if(!r.keySet().equals(Set.of("actorId","requestId","operation","canonicalBodyHash","reply","persistenceMode","durable"))
                ||!request.toString().equals(r.get("requestId"))||!VirtualTransactionalStore.MODE.equals(r.get("persistenceMode"))
                ||!Boolean.FALSE.equals(r.get("durable"))||!text(r,"canonicalBodyHash").matches("[0-9a-f]{64}"))throw bad();
        text(r,"actorId");text(r,"operation");var reply=map(r.get("reply"));
        if(!request.toString().equals(reply.get("requestId"))||!(reply.get("replayed") instanceof Boolean))throw bad();return r;
    }
    private static void own(TransactionalStore.Tx tx,Scope expected,Scope historical) {
        if(!historical.workflowId().equals(expected.workflowId())||!historical.customerId().equals(expected.customerId())
                ||historical.generation()>expected.generation())throw bad();VirtualGrantGenerationHistory.validate(tx,historical);
    }
    private static final class Rows {
        private record Entry(Map<String,Object> row,int generation,String identity) { }
        private final String key;private final boolean event;private final Map<String,Entry> rows=new LinkedHashMap<>();
        Rows(String key){this(key,false);}
        Rows(String key,boolean event){this.key=key;this.event=event;}
        void add(Map<String,Object> value){add(value,value.get("generation") instanceof Integer n?n:-1);}
        void add(Map<String,Object> value,int generation){String source=text(value,key);
            String id=event?text(value,"eventType")+"|"+text(value,"workflowId")+"|"+(generation<0?"*":generation)+"|"+source:source;
            var entry=new Entry(CanonicalJson.immutableObject(value),generation,id);var old=rows.putIfAbsent(id,entry);
            if(old!=null&&(!old.row().equals(value)||old.generation()!=generation))throw bad();}
        List<Map<String,Object>> values(){return rows.values().stream().sorted(Comparator.comparingInt(Entry::generation)
                .thenComparing(e->text(e.row(),key)).thenComparing(Entry::identity)).map(Entry::row).toList();}
    }
    private static Scope scope(Map<String,Object> r){return new Scope(uuid(r,"workflowId"),positive(r,"generation"),text(r,"customerId"));}
    private static UUID canonical(String s){UUID id=UUID.fromString(s);if(!id.toString().equals(s))throw bad();return id;}
    private static UUID uuid(Map<String,Object>r,String key){return canonical(text(r,key));}
    private static String text(Map<String,Object>r,String key){if(!(r.get(key) instanceof String s)||s.isBlank())throw bad();return s;}
    private static int nonnegative(Map<String,Object>r,String key){if(!(r.get(key)instanceof Integer n)||n<0)throw bad();return n;}
    private static int positive(Map<String,Object>r,String key){int n=nonnegative(r,key);if(n<1)throw bad();return n;}
    @SuppressWarnings("unchecked") private static Map<String,Object> map(Object raw){if(!(raw instanceof Map<?,?> m))throw bad();for(var k:m.keySet())if(!(k instanceof String))throw bad();return(Map<String,Object>)m;}
    private static Map<String,Object> row(Object... values){var out=new LinkedHashMap<String,Object>();if(values.length%2!=0)throw bad();for(int i=0;i<values.length;i+=2){if(!(values[i]instanceof String k)||out.containsKey(k))throw bad();out.put(k,values[i+1]);}return out;}
    private static SimulationFailure bad(){return SimulationFailure.unavailable();}
}
