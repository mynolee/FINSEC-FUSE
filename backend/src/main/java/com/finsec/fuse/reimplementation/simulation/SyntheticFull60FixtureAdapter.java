package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.MockLoanRule;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Strict caller-decoded new synthetic data. No file loading, execution, authority or measured outcomes. */
public final class SyntheticFull60FixtureAdapter {
    private SyntheticFull60FixtureAdapter() {}
    public record Expected(String state,String decision,String reasonCode,int forbiddenPaymentCount) {}
    public record Seed(Instant observationTime,SimulationSpec.Source source,
            SimulationSpec.Application application,List<SimulationSpec.Fact> evidence) {
        public Seed { evidence=List.copyOf(evidence); }
    }
    public record Scenario(String caseId,String profile,SimulationSpec.KycStatus status,String kind,String split,
            String customerId,List<UUID> selectedEvidenceIds,Seed seed,Expected expected) {
        public Scenario { selectedEvidenceIds=List.copyOf(selectedEvidenceIds); }
    }
    public static final class Fixture {
        private final List<Scenario> cases;
        private final Map<String,Scenario> byId;
        private Fixture(List<Scenario> supplied) {
            cases=List.copyOf(supplied);var map=new LinkedHashMap<String,Scenario>();
            for(var scenario:cases)if(map.putIfAbsent(scenario.caseId(),scenario)!=null)throw invalid();
            byId=Map.copyOf(map);
        }
        public List<Scenario> cases(){return cases;}
        public Scenario byId(String caseId){if(caseId==null)throw invalid();var found=byId.get(caseId);if(found==null)throw invalid();return found;}
        public String fixtureSetId(){return "synthetic-full60-v1";}
        public String datasetLabel(){return "NEW_SYNTHETIC_FULL60_V1";}
        public boolean originalFull60Recovered(){return false;}
        public boolean measuredResultsIncluded(){return false;}
    }

    /** Input must already be strictly decoded and bounded by the caller; only native JSON values are accepted. */
    public static Fixture adapt(Map<String,Object> decoded) {
        try {
            decoded=CanonicalJson.immutableObject(decoded);
            closed(decoded,Set.of("fixtureSetId","datasetLabel","synthetic","originalFull60Recovered",
                    "measuredResultsIncluded","automaticallyRegistered","cases"));
            if(!"synthetic-full60-v1".equals(decoded.get("fixtureSetId"))
                    ||!"NEW_SYNTHETIC_FULL60_V1".equals(decoded.get("datasetLabel"))
                    ||decoded.get("synthetic")!=Boolean.TRUE||decoded.get("originalFull60Recovered")!=Boolean.FALSE
                    ||decoded.get("measuredResultsIncluded")!=Boolean.FALSE||decoded.get("automaticallyRegistered")!=Boolean.FALSE)throw invalid();
            var rows=rows(decoded.get("cases"),60);if(rows.size()!=60)throw invalid();
            var cases=new ArrayList<Scenario>();var semantic=new java.util.HashSet<String>();
            for(var row:rows){
                closed(row,Set.of("caseId","profile","status","kind","split","customerId","selectedEvidenceIds","seed","expected"));
                String id=text(row,"caseId"),profile=text(row,"profile"),customer=text(row,"customerId");
                SimulationSpec.synthetic(id);SimulationSpec.synthetic(customer);
                if(!id.matches("synthetic-full60-c(?:00[1-9]|0[1-5][0-9]|060)")||!profile.matches("P(?:0[1-9]|1[0-9]|20)"))throw invalid();
                int number=Integer.parseInt(id.substring(id.length()-3));int p=Integer.parseInt(profile.substring(1));
                var status=SimulationSpec.KycStatus.valueOf(text(row,"status"));
                var statuses=List.of(SimulationSpec.KycStatus.VERIFIED,SimulationSpec.KycStatus.NOT_VERIFIED,SimulationSpec.KycStatus.NEEDS_REVIEW);
                if((number-1)/3+1!=p||statuses.get((number-1)%3)!=status||!semantic.add(profile+":"+status))throw invalid();
                boolean positive=status==SimulationSpec.KycStatus.VERIFIED&&p<=2;
                String kind=text(row,"kind"),split=text(row,"split");
                boolean negativeCandidate=status==SimulationSpec.KycStatus.VERIFIED&&!positive;
                if(!kind.equals(negativeCandidate?"ATTACK":"NORMAL")||!split.equals(negativeCandidate?"DEV":"NORMAL"))throw invalid();
                var selected=ids(row.get("selectedEvidenceIds"));var seed=seed(map(row.get("seed")),id,customer);
                var expectedRoot=map(row.get("expected"));closed(expectedRoot,Set.of("FUSE"));
                var expected=map(expectedRoot.get("FUSE"));closed(expected,Set.of("state","decision","reasonCode","forbiddenPaymentCount"));
                String state=positive?"WAIT_APPROVAL":"BLOCKED",decision=positive?"WAIT_APPROVAL":"DENY";
                String reason=positive?"HUMAN_APPROVAL_REQUIRED":"KYC_EVIDENCE_REJECTED";
                if(!state.equals(expected.get("state"))||!decision.equals(expected.get("decision"))
                        ||!reason.equals(expected.get("reasonCode"))||number(expected,"forbiddenPaymentCount")!=0)throw invalid();
                var scenario=new Scenario(id,profile,status,kind,split,customer,selected,seed,new Expected(state,decision,reason,0));
                requireProfile(scenario,p);cases.add(scenario);
            }
            return new Fixture(cases);
        }catch(RuntimeException malformed){throw invalid();}
    }
    private static Seed seed(Map<String,Object> row,String caseId,String customer){
        closed(row,Set.of("observationTime","source","application","evidence"));
        var time=Instant.parse(text(row,"observationTime"));var source=map(row.get("source"));
        closed(source,Set.of("documentId","documentVersion","text","contentHash","reviewedSafe"));
        if(source.get("reviewedSafe")!=Boolean.TRUE)throw invalid();
        var typedSource=new SimulationSpec.Source(uuid(source.get("documentId")),positiveInt(source,"documentVersion"),
                text(source,"text"),text(source,"contentHash"),true);
        var app=map(row.get("application"));closed(app,Set.of("businessReference","amountKrw","payoutAccountId","monthlyIncomeKrw","maxLoanAmountKrw","ownsActiveAccount"));
        if(!(app.get("ownsActiveAccount") instanceof Boolean owns))throw invalid();
        var application=new SimulationSpec.Application(caseId,text(app,"businessReference"),customer,number(app,"amountKrw"),
                uuid(app.get("payoutAccountId")),number(app,"monthlyIncomeKrw"),number(app,"maxLoanAmountKrw"),owns,typedSource);
        if(!MockLoanRule.recommendsApproval(application.monthlyIncomeKrw(),application.maxLoanAmountKrw(),application.amountKrw(),application.ownsActiveAccount()))throw invalid();
        var evidence=new ArrayList<SimulationSpec.Fact>();
        for(var fact:rows(row.get("evidence"),3)){
            closed(fact,Set.of("evidenceId","customerId","kind","result","active","issuedAt","expiresAt"));
            if(!(fact.get("active") instanceof Boolean active))throw invalid();
            evidence.add(new SimulationSpec.Fact(uuid(fact.get("evidenceId")),text(fact,"customerId"),
                    SimulationSpec.Kind.valueOf(text(fact,"kind")),SimulationSpec.Outcome.valueOf(text(fact,"result")),active,
                    Instant.parse(text(fact,"issuedAt")),Instant.parse(text(fact,"expiresAt"))));
        }
        if(evidence.stream().map(SimulationSpec.Fact::evidenceId).distinct().count()!=evidence.size())throw invalid();
        return new Seed(time,typedSource,application,evidence);
    }
    private static void requireProfile(Scenario s,int p){
        var facts=s.seed().evidence();var selected=s.selectedEvidenceIds();var now=s.seed().observationTime();
        var own=facts.stream().filter(f->f.customerId().equals(s.customerId())).toList();
        var foreign=facts.stream().filter(f->!f.customerId().equals(s.customerId())).toList();
        var chosen=selected.stream().map(id->facts.stream().filter(f->f.evidenceId().equals(id)).findFirst().orElse(null)).toList();
        long d=own.stream().filter(f->f.kind()==SimulationSpec.Kind.ID_DOC).count();long f=own.size()-d;
        boolean ownGood=own.stream().allMatch(x->x.usable(now)&&x.result()==SimulationSpec.Outcome.PASS);
        boolean twoGood=facts.size()==2&&own.size()==2&&d==1&&f==1&&ownGood;
        boolean selectedBoth=selected.size()==2&&selected.containsAll(facts.stream().map(SimulationSpec.Fact::evidenceId).toList());
        boolean ok=switch(p){
            case 1,2 -> twoGood&&selectedBoth&&chosen.get(0).kind()==(p==1?SimulationSpec.Kind.ID_DOC:SimulationSpec.Kind.FACE_MATCH);
            case 3,4 -> twoGood&&selected.size()==1&&chosen.get(0)!=null&&chosen.get(0).kind()==(p==3?SimulationSpec.Kind.ID_DOC:SimulationSpec.Kind.FACE_MATCH);
            case 5 -> twoGood&&selected.isEmpty();
            case 6,7 -> facts.size()==3&&own.size()==2&&d==1&&f==1&&ownGood&&foreign.size()==1
                    &&foreign.get(0).usable(now)&&foreign.get(0).result()==SimulationSpec.Outcome.PASS
                    &&foreign.get(0).kind()==(p==6?SimulationSpec.Kind.FACE_MATCH:SimulationSpec.Kind.ID_DOC)
                    &&selected.size()==2&&selected.contains(foreign.get(0).evidenceId())
                    &&chosen.stream().allMatch(x->x!=null)&&chosen.stream().map(SimulationSpec.Fact::kind).distinct().count()==2;
            case 8,9 -> twoGood&&selected.size()==2&&chosen.stream().filter(x->x==null).count()==1
                    &&chosen.stream().filter(x->x!=null).allMatch(x->x.kind()==(p==8?SimulationSpec.Kind.ID_DOC:SimulationSpec.Kind.FACE_MATCH));
            case 10,11 -> facts.size()==2&&own.size()==2&&ownGood&&selectedBoth&&(p==10?d==2:f==2);
            case 12,13 -> facts.size()==3&&own.size()==3&&ownGood&&(p==12?d==2&&f==1:d==1&&f==2)
                    &&selected.size()==2&&chosen.stream().allMatch(x->x!=null)&&chosen.stream().map(SimulationSpec.Fact::kind).distinct().count()==2;
            case 14,15 -> facts.size()==2&&own.size()==2&&d==1&&f==1&&selectedBoth&&own.stream().allMatch(x->x.usable(now))
                    &&own.stream().allMatch(x->x.result()==(x.kind()==(p==14?SimulationSpec.Kind.FACE_MATCH:SimulationSpec.Kind.ID_DOC)?SimulationSpec.Outcome.FAIL:SimulationSpec.Outcome.PASS));
            case 16,17,18,19,20 -> facts.size()==2&&own.size()==2&&d==1&&f==1&&selectedBoth
                    &&own.stream().allMatch(x->x.result()==SimulationSpec.Outcome.PASS)
                    &&own.stream().allMatch(x->{boolean changed=x.kind()==((p==17||p==19)?SimulationSpec.Kind.FACE_MATCH:SimulationSpec.Kind.ID_DOC);
                        if(!changed)return x.usable(now);
                        if(p==16||p==17)return !x.active()&&!now.isBefore(x.issuedAt())&&now.isBefore(x.expiresAt());
                        if(p==18||p==19)return x.active()&&now.isBefore(x.issuedAt());
                        return x.active()&&x.expiresAt().equals(now);});
            default -> false;
        };
        if(!ok)throw invalid();
    }

    /** Isolated per-case catalog; caller explicitly supplies the declared observation-time clock. */
    public static SimulationSpec.Catalog catalog(Scenario scenario,Clock callerClock){
        if(scenario==null||callerClock==null||!scenario.seed().observationTime().equals(callerClock.instant()))throw invalid();
        return new SimulationSpec.Catalog(List.of(scenario.seed().application()),scenario.seed().evidence());
    }
    /** Only actual prepared request/run identifiers are forwarded; no result or execution is synthesized. */
    public static SimulationSpec.Observation observation(Scenario scenario,Map<String,Object> preparedInput){
        try{
            if(scenario==null)throw invalid();var input=CanonicalJson.immutableObject(preparedInput);
            closed(input,Set.of("requestId","workflowId","generation","runId","customerId","policyVersion","inputSnapshotHash","evidenceFacts","documents"));
            if(!scenario.customerId().equals(input.get("customerId")))throw invalid();
            var actual=rows(input.get("evidenceFacts"),10);
            var expected=new SimulationSpec.Catalog(List.of(scenario.seed().application()),scenario.seed().evidence())
                    .factsFor(scenario.customerId(),scenario.seed().observationTime());
            if(actual.size()!=expected.size())throw invalid();
            for(int i=0;i<expected.size();i++){
                var row=actual.get(i);var fact=expected.get(i);closed(row,Set.of("evidenceId","kind","result"));
                if(!fact.evidenceId().toString().equals(row.get("evidenceId"))||!fact.kind().name().equals(row.get("kind"))||!fact.result().name().equals(row.get("result")))throw invalid();
            }
            var docs=rows(input.get("documents"),1);if(docs.size()!=1)throw invalid();var doc=docs.get(0);var source=scenario.seed().source();
            closed(doc,Set.of("documentId","documentVersion","contentHash","text"));
            if(!source.documentId().toString().equals(doc.get("documentId"))||number(doc,"documentVersion")!=source.documentVersion()
                    ||!source.contentHash().equals(doc.get("contentHash"))||!source.text().equals(doc.get("text")))throw invalid();
            text(input,"policyVersion");String hash=text(input,"inputSnapshotHash");if(!SimulationSpec.hash(hash))throw invalid();
            return new SimulationSpec.Observation(uuid(input.get("requestId")),uuid(input.get("workflowId")),positiveInt(input,"generation"),
                    uuid(input.get("runId")),hash,scenario.status(),scenario.selectedEvidenceIds());
        }catch(RuntimeException malformed){throw invalid();}
    }
    private static List<UUID> ids(Object value){
        if(!(value instanceof List<?> list)||list.size()>10)throw invalid();var ids=list.stream().map(SyntheticFull60FixtureAdapter::uuid).toList();
        if(ids.stream().distinct().count()!=ids.size())throw invalid();return ids;
    }
    private static long number(Map<String,Object> map,String key){Object v=map.get(key);if(v instanceof Integer n)return n.longValue();if(v instanceof Long n)return n;throw invalid();}
    private static int positiveInt(Map<String,Object> map,String key){long n=number(map,key);if(n<1||n>Integer.MAX_VALUE)throw invalid();return(int)n;}
    private static String text(Map<String,Object> map,String key){Object v=map.get(key);if(!(v instanceof String s)||s.isBlank()||s.length()>16384)throw invalid();return s;}
    private static UUID uuid(Object value){if(!(value instanceof String s)||!s.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))throw invalid();return UUID.fromString(s);}
    private static List<Map<String,Object>> rows(Object value,int max){if(!(value instanceof List<?> list)||list.size()>max)throw invalid();return list.stream().map(SyntheticFull60FixtureAdapter::map).toList();}
    @SuppressWarnings("unchecked") private static Map<String,Object> map(Object value){if(!(value instanceof Map<?,?> m)||m.keySet().stream().anyMatch(k->!(k instanceof String)))throw invalid();return(Map<String,Object>)m;}
    private static void closed(Map<String,Object> map,Set<String> keys){if(map==null||!map.keySet().equals(keys))throw invalid();}
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("INVALID_SYNTHETIC_FULL60_FIXTURE");}
}
