package com.finsec.fuse.quarantine;

import static com.finsec.fuse.payment.PaymentValues.*;
import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.persistence.Db;
import java.util.*;
import org.springframework.stereotype.Component;

/** Only recorded provenance and dependency edges contribute to actual impact. */
@Component
public class ImpactGraph {
    private final Db db; private final FusePolicy policy;
    public ImpactGraph(Db db,FusePolicy policy) {this.db=db;this.policy=policy;}
    public record Affected(List<Map<String,Object>> runs, Set<UUID> historicalRunIds,
        Set<UUID> currentWorkflowIds,Set<UUID> historicalWorkflowIds,Set<UUID> heldWorkflowIds) {}
    public Affected affected(Map<String,Object> target) {
        String scope=str(target,"scope");String seed;Object[] args;
        switch(scope) {
            case "RUN" -> {seed="select id as run_id from agent_run where id=?";args=new Object[]{uuid(target,"run_id")};}
            case "RESULT" -> {seed="select run_id from agent_result where id=?";args=new Object[]{uuid(target,"result_id")};}
            case "WORKFLOW" -> {seed="select id as run_id from agent_run where workflow_id=?";args=new Object[]{uuid(target,"workflow_id")};}
            case "SOURCE_VERSION" -> {seed="select run_id from run_source_use where document_id=? and document_version=?";args=new Object[]{uuid(target,"document_id"),integer(target,"document_version")};}
            case "AGENT_VERSION" -> {seed="select id as run_id from agent_run where agent_id=? and agent_version=?";args=new Object[]{str(target,"agent_id"),integer(target,"agent_version")};}
            default -> throw new ApiException(400,"INVALID_REQUEST","Unknown quarantine scope.");
        }
        var rows=db.query("with recursive affected(run_id) as ("+seed+" union select d.child_run_id from run_dependency d join affected a on d.parent_run_id=a.run_id) "+
            "select r.*,w.generation as current_generation,w.state as workflow_state,k.run_id as current_kyc_run,l.run_id as current_loan_run,a.customer_id,a.amount_krw "+
            "from affected f join agent_run r on r.id=f.run_id join workflow w on w.id=r.workflow_id join loan_application a on a.id=w.application_id "+
            "left join agent_result k on k.id=w.current_kyc_result_id left join agent_result l on l.id=w.current_loan_result_id order by r.workflow_id,r.created_at,r.id",args);
        Set<UUID> runIds=new LinkedHashSet<>(),current=new TreeSet<>(Comparator.comparing(UUID::toString)),historical=new TreeSet<>(Comparator.comparing(UUID::toString));
        for(var row:rows) {runIds.add(uuid(row,"id"));historical.add(uuid(row,"workflow_id"));}
        for(var row:rows) if(integer(row,"generation")==integer(row,"current_generation") || runIds.contains(uuid(row,"current_kyc_run")) || runIds.contains(uuid(row,"current_loan_run"))) current.add(uuid(row,"workflow_id"));
        if("WORKFLOW".equals(scope)) {current.add(uuid(target,"workflow_id"));historical.add(uuid(target,"workflow_id"));}
        Set<UUID> held=new TreeSet<>(Comparator.comparing(UUID::toString));
        if(uuid(target,"id")!=null)for(var hold:db.query("select h.workflow_id,h.generation,w.generation current_generation from quarantine_workflow_hold h join workflow w on w.id=h.workflow_id where h.quarantine_id=?",uuid(target,"id"))) {
            held.add(uuid(hold,"workflow_id"));
            if(integer(hold,"generation")==integer(hold,"current_generation"))current.add(uuid(hold,"workflow_id"));
        }
        return new Affected(rows,runIds,current,historical,held);
    }
    public Map<String,Object> describe(UUID quarantineId) {
        var quarantine=db.required("select * from quarantine where id=?",quarantineId);
        var affected=affected(quarantine);
        var runs=affected.runs().stream().filter(r->r.get("started_at")!=null).toList();
        Set<String> roles=new TreeSet<>(),customers=new TreeSet<>();Set<UUID> actualWorkflows=new TreeSet<>(Comparator.comparing(UUID::toString));actualWorkflows.addAll(affected.historicalWorkflowIds());
        List<Map<String,Object>> nodes=new ArrayList<>(),edges=new ArrayList<>(),payments=new ArrayList<>();Set<String> sourceKeys=new HashSet<>();
        for(var run:runs) {
            UUID runId=uuid(run,"id");roles.add(str(run,"role"));customers.add(str(run,"customer_id"));actualWorkflows.add(uuid(run,"workflow_id"));
            nodes.add(Json.ordered("id",runId,"type","AGENT_RUN","role",str(run,"role"),"generation",integer(run,"generation"),"status",str(run,"status")));
            for(var source:db.query("select * from run_source_use where run_id=?",runId)) {
                String key=uuid(source,"document_id")+":"+integer(source,"document_version");
                if(sourceKeys.add(key))nodes.add(Json.ordered("id",key,"type","SOURCE_VERSION","documentId",uuid(source,"document_id"),"documentVersion",integer(source,"document_version")));
                edges.add(Json.ordered("from",key,"to",runId,"type","ACTUAL_DOCUMENT_USE"));
            }
            for(var result:db.query("select * from agent_result where run_id=?",runId)) {
                nodes.add(Json.ordered("id",uuid(result,"id"),"type","RESULT","status",str(result,"status")));
                edges.add(Json.ordered("from",runId,"to",uuid(result,"id"),"type","PRODUCED_RESULT"));
            }
            for(var dependency:db.query("select * from run_dependency where parent_run_id=?",runId)) if(affected.historicalRunIds().contains(uuid(dependency,"child_run_id")))
                edges.add(Json.ordered("from",uuid(dependency,"parent_result_id"),"to",uuid(dependency,"child_run_id"),"parentRunId",runId,"type","ACTUAL_RESULT_USE"));
            for(var payment:db.query("select * from mock_payment where run_id=?",runId)) {
                payments.add(payment);nodes.add(Json.ordered("id",uuid(payment,"id"),"type","MOCK_PAYMENT","amountKrw",number(payment,"amount_krw")));
                edges.add(Json.ordered("from",runId,"to",uuid(payment,"id"),"type","ACTUAL_PAYMENT"));
            }
        }
        long pendingAmount=0;
        for(UUID workflowId:actualWorkflows) {
            var app=db.required("select a.*,w.state from workflow w join loan_application a on a.id=w.application_id where w.id=?",workflowId);
            customers.add(str(app,"customer_id"));
            nodes.add(Json.ordered("id",workflowId,"type","WORKFLOW","state",str(app,"state")));
            if(!"PAID".equals(str(app,"state")))pendingAmount+=number(app,"amount_krw");
        }
        long paidAmount=payments.stream().mapToLong(p->number(p,"amount_krw")).sum();
        List<Map<String,Object>> paidBefore=payments.stream().filter(p->!instant(p,"created_at").isAfter(instant(quarantine,"created_at")))
            .map(p->(Map<String,Object>)Json.ordered("workflowId",uuid(p,"workflow_id"),"paymentId",uuid(p,"id"),"amountKrw",number(p,"amount_krw"),"paidBeforeQuarantine",true)).toList();
        Set<String> potentialCustomers=new TreeSet<>(customers),potentialOrigins=new TreeSet<>(roles);
        for(UUID heldId:affected.heldWorkflowIds())potentialCustomers.add(str(db.required("select a.customer_id from workflow w join loan_application a on a.id=w.application_id where w.id=?",heldId),"customer_id"));
        if(potentialOrigins.isEmpty() && !affected.heldWorkflowIds().isEmpty()) {
            if("SOURCE_VERSION".equals(str(quarantine,"scope")))potentialOrigins.add("KYC");
            else if("AGENT_VERSION".equals(str(quarantine,"scope")))potentialOrigins.add(str(db.required("select role from agent_registry where agent_id=? and version=?",str(quarantine,"agent_id"),integer(quarantine,"agent_version")),"role"));
        }
        var potential=potential(potentialOrigins,potentialCustomers);
        potential.putAll(potentialApplications(affected));
        return Json.ordered("incidentId",quarantineId,"scope",str(quarantine,"scope"),"target",targetView(quarantine),
            "historicalRunIds",affected.historicalRunIds(),"currentAffectedWorkflowIds",affected.currentWorkflowIds(),"policyHeldWorkflowIds",affected.heldWorkflowIds(),"paidBeforeQuarantine",paidBefore,
            "actual",Json.ordered("runCount",runs.size(),"roleCount",roles.size(),"workflowCount",actualWorkflows.size(),"customerCount",customers.size(),"paymentCount",payments.size(),"paidAmountKrw",paidAmount,"atRiskPendingAmountKrw",pendingAmount),
            "potential",potential,"nodes",nodes,"edges",edges,"potentialNodes",potential.get("roles"),
            "calculationRefs",Json.ordered("source","run_source_use","dependencies","run_dependency","policyHolds","quarantine_workflow_hold","payments","mock_payment","policyVersion",policy.policyVersion(),"preparedRunsExcluded",affected.runs().size()-runs.size()));
    }
    private Map<String,Object> potential(Set<String> actualRoles,Set<String> customers) {
        Set<String> reachable=new LinkedHashSet<>();int maxDepth=0;
        for(String role:actualRoles) {var frontier=new ArrayDeque<Map.Entry<String,Integer>>();frontier.add(Map.entry(role,0));Set<String> visited=new HashSet<>();
            while(!frontier.isEmpty()) {var entry=frontier.remove();if(!visited.add(entry.getKey()))continue;
                for(String next:policy.allowedEdges().getOrDefault(entry.getKey(),List.of())) {reachable.add(next);int depth=entry.getValue()+1;maxDepth=Math.max(maxDepth,depth);frontier.add(Map.entry(next,depth));}
            }
        }
        Set<String> registered=new TreeSet<>();
        for(String customer:customers) if(db.one("select customer_id from application_registry where customer_id=? limit 1",customer).isPresent())registered.add(customer);
        return Json.ordered("roles",reachable,"maxDownstreamDepth",maxDepth,"registeredCustomerCount",registered.size(),"perApplicationLimitKrw",policy.maxAmountKrw(),"missingPolicyFields",List.of());
    }
    /**
     * Monetary potential is limited to existing applications in this incident's recorded impact
     * or policy-hold scope, using CURRENT workflow state. Registry-only and unrelated applications
     * of the same customer are deliberately excluded. Retries, generations, runs and holds cannot
     * multiply an application: both aggregates consume the same distinct application-id rows.
     */
    Map<String,Object> potentialApplications(Affected affected) {
        Set<UUID> workflowIds=new TreeSet<>(Comparator.comparing(UUID::toString));
        workflowIds.addAll(affected.currentWorkflowIds());
        workflowIds.addAll(affected.historicalWorkflowIds());
        workflowIds.addAll(affected.heldWorkflowIds());
        // A bound PostgreSQL UUID array also supports empty and large scopes without one bind per ID.
        String scope=workflowIds.stream().map(UUID::toString).collect(java.util.stream.Collectors.joining(",","{","}"));
        var aggregate=db.required("with eligible_applications as ("+
            "select distinct a.id,a.amount_krw from loan_application a join workflow w on w.application_id=a.id "+
            "where w.id=any(cast(? as uuid[])) and w.state in "+
            "('KYC_PENDING','KYC_VALIDATED','REVIEW_READY','WAIT_APPROVAL','APPROVED','PAYMENT_RESERVED','BLOCKED','ON_HOLD')) "+
            "select count(*) as application_count,coalesce(sum(amount_krw),0)::text as total_amount_krw from eligible_applications",scope);
        // PostgreSQL SUM(bigint) is arbitrary-precision numeric; a decimal string preserves it in JS.
        return Json.ordered("applicationCount",number(aggregate,"application_count"),
            "totalAmountKrw",str(aggregate,"total_amount_krw"),"currency","KRW");
    }
    public Map<String,Object> targetView(Map<String,Object> target) {
        return switch(str(target,"scope")) {
            case "RUN" -> Json.ordered("runId",uuid(target,"run_id"));
            case "RESULT" -> Json.ordered("resultId",uuid(target,"result_id"));
            case "WORKFLOW" -> Json.ordered("workflowId",uuid(target,"workflow_id"));
            case "SOURCE_VERSION" -> Json.ordered("documentId",uuid(target,"document_id"),"documentVersion",integer(target,"document_version"));
            case "AGENT_VERSION" -> Json.ordered("agentId",str(target,"agent_id"),"agentVersion",integer(target,"agent_version"));
            default -> throw new ApiException(400,"INVALID_REQUEST","Unknown quarantine scope.");
        };
    }
}
