package com.finsec.fuse.reimplementation.simulation;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.*;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;

/** New synthetic fixture admission only; no service execution, original recovery or measured outcomes. */
final class SyntheticFull60FixtureAdapterTest {
    @SuppressWarnings("unchecked")
    private Map<String,Object> decoded() throws Exception {
        byte[] bytes=Files.readAllBytes(Path.of("../evaluation/fixtures/synthetic-full60-v1.json"));
        assertTrue(bytes.length<=131072,"Fixed public test input budget only");
        // Existing project test decoder convention; strict duplicate-key transport is not tested here.
        return JsonMapper.builder().build().readValue(bytes,Map.class);
    }
    @SuppressWarnings("unchecked") private static Map<String,Object> map(Object value) {return (Map<String,Object>)value;}
    @SuppressWarnings("unchecked") private static List<Object> list(Object value) {return (List<Object>)value;}
    private static Map<String,Object> row(Map<String,Object> root,int index) {return map(list(root.get("cases")).get(index));}
    private static Map<String,Object> seed(Map<String,Object> root,int index) {return map(row(root,index).get("seed"));}
    private static Map<String,Object> fact(Map<String,Object> root,int index,int evidence) {return map(list(seed(root,index).get("evidence")).get(evidence));}
    private void rejects(Consumer<Map<String,Object>> mutation) throws Exception {
        var document=decoded();
        assertEquals(60,SyntheticFull60FixtureAdapter.adapt(document).cases().size(),"Positive admission before mutation");
        mutation.accept(document);
        var error=assertThrows(IllegalArgumentException.class,()->SyntheticFull60FixtureAdapter.adapt(document));
        assertEquals("INVALID_SYNTHETIC_FULL60_FIXTURE",error.getMessage());assertNull(error.getCause());
    }
    private Map<String,Object> prepared(SyntheticFull60FixtureAdapter.Scenario scenario) {
        var source=scenario.seed().source();
        var catalog=SyntheticFull60FixtureAdapter.catalog(scenario,Clock.fixed(scenario.seed().observationTime(),ZoneOffset.UTC));
        return object("requestId",new UUID(0,101).toString(),"workflowId",new UUID(0,102).toString(),
            "generation",2,"runId",new UUID(0,103).toString(),"customerId",scenario.customerId(),
            "policyVersion","SYNTHETIC-TEST-ONLY","inputSnapshotHash","a".repeat(64),
            "evidenceFacts",catalog.factsFor(scenario.customerId(),scenario.seed().observationTime()).stream()
                .map(f->object("evidenceId",f.evidenceId().toString(),"kind",f.kind().name(),"result",f.result().name())).toList(),
            "documents",List.of(object("documentId",source.documentId().toString(),"documentVersion",source.documentVersion(),
                "contentHash",source.contentHash(),"text",source.text())));
    }
    private void rejectsPrepared(SyntheticFull60FixtureAdapter.Scenario scenario,Consumer<Map<String,Object>> mutation) {
        var input=new LinkedHashMap<>(prepared(scenario));
        assertNotNull(SyntheticFull60FixtureAdapter.observation(scenario,input));
        mutation.accept(input);
        var error=assertThrows(IllegalArgumentException.class,()->SyntheticFull60FixtureAdapter.observation(scenario,input));
        assertEquals("INVALID_SYNTHETIC_FULL60_FIXTURE",error.getMessage());assertNull(error.getCause());
    }
    @Test void constructsAllSixtyExplicitCasesAndTwentyProfilesWithThreeStatusesWithoutObservedResults() throws Exception {
        var fixture=SyntheticFull60FixtureAdapter.adapt(decoded());
        assertEquals("synthetic-full60-v1",fixture.fixtureSetId());assertEquals("NEW_SYNTHETIC_FULL60_V1",fixture.datasetLabel());
        assertFalse(fixture.originalFull60Recovered());assertFalse(fixture.measuredResultsIncluded());
        assertEquals(60,fixture.cases().size());assertEquals(60,fixture.cases().stream().map(s->s.caseId()).distinct().count());
        assertEquals(20,fixture.cases().stream().map(s->s.profile()).distinct().count());
        assertEquals(18,fixture.cases().stream().filter(s->s.kind().equals("ATTACK")).count());
        assertEquals(42,fixture.cases().stream().filter(s->s.kind().equals("NORMAL")).count());
        var statuses=List.of(SimulationSpec.KycStatus.VERIFIED,SimulationSpec.KycStatus.NOT_VERIFIED,SimulationSpec.KycStatus.NEEDS_REVIEW);
        for(int index=0;index<60;index++) {
            var scenario=fixture.cases().get(index);
            assertEquals(String.format(java.util.Locale.ROOT,"synthetic-full60-c%03d",index+1),scenario.caseId());
            assertEquals(statuses.get(index%3),scenario.status());assertSame(scenario,fixture.byId(scenario.caseId()));
            boolean favorable=index==0||index==3;
            assertEquals(favorable?"WAIT_APPROVAL":"BLOCKED",scenario.expected().state());
            assertEquals(0,scenario.expected().forbiddenPaymentCount());
        }
    }
    @Test void perCaseCatalogContainsOnlyItsApplicationSourceAndFacts() throws Exception {
        var fixture=SyntheticFull60FixtureAdapter.adapt(decoded());
        for(int index=0;index<60;index++) {
            var s=fixture.cases().get(index);var other=fixture.cases().get((index+1)%60);
            var catalog=SyntheticFull60FixtureAdapter.catalog(s,Clock.fixed(s.seed().observationTime(),ZoneOffset.UTC));
            assertEquals(List.of(s.seed().application()),catalog.applications());
            assertEquals(s.seed().application(),catalog.application(s.seed().application().request()));
            assertEquals(s.seed().source(),catalog.source(s.seed().source().documentId(),s.seed().source().documentVersion()));
            for(var f:s.seed().evidence())assertEquals(f,catalog.fact(f.evidenceId()));
            // Fixture intentionally shares one reviewed source across cases; isolation is not invented source uniqueness.
            assertEquals(s.seed().source(),other.seed().source());
            assertNull(catalog.source(new UUID(0,9999),1));
            assertThrows(IllegalArgumentException.class,()->catalog.application(other.seed().application().request()));
            for(var f:other.seed().evidence())assertNull(catalog.fact(f.evidenceId()));
        }
    }
    @Test void observationForAllCasesForwardsOnlyExplicitPreparedIdentityAndDeclaredSelection() throws Exception {
        var fixture=SyntheticFull60FixtureAdapter.adapt(decoded());
        for(var s:fixture.cases()) {
            var input=prepared(s);var before=new LinkedHashMap<>(input);
            var observed=SyntheticFull60FixtureAdapter.observation(s,input);
            assertEquals(new UUID(0,101),observed.requestId());assertEquals(new UUID(0,102),observed.workflowId());
            assertEquals(2,observed.generation());assertEquals(new UUID(0,103),observed.runId());
            assertEquals("a".repeat(64),observed.inputSnapshotHash());assertEquals(s.status(),observed.status());
            assertEquals(s.selectedEvidenceIds(),observed.evidenceIds());assertEquals(before,input);
        }
    }
    @Test void fixtureAndNestedListsAreImmutableAndDecodedInputIsSnapshotted() throws Exception {
        var document=decoded();var fixture=SyntheticFull60FixtureAdapter.adapt(document);var first=fixture.cases().get(0);
        assertThrows(UnsupportedOperationException.class,()->fixture.cases().clear());
        assertThrows(UnsupportedOperationException.class,()->first.selectedEvidenceIds().clear());
        assertThrows(UnsupportedOperationException.class,()->first.seed().evidence().clear());
        String sourceBefore=first.seed().source().text();
        map(seed(document,0).get("source")).put("text","synthetic-mutated-source");
        row(document,0).put("customerId","synthetic-mutated");list(document.get("cases")).clear();
        assertEquals(60,fixture.cases().size());assertNotEquals("synthetic-mutated",first.customerId());
        assertEquals(sourceBefore,first.seed().source().text());
        assertEquals(first,fixture.byId(first.caseId()));
        var error=assertThrows(IllegalArgumentException.class,()->fixture.byId("synthetic-unknown"));
        assertEquals("INVALID_SYNTHETIC_FULL60_FIXTURE",error.getMessage());
        var nullLookup=assertThrows(IllegalArgumentException.class,()->fixture.byId(null));
        assertEquals("INVALID_SYNTHETIC_FULL60_FIXTURE",nullLookup.getMessage());assertNull(nullLookup.getCause());
    }
    @Test void missingDuplicateRenamedTruncatedAndExtraCaseShapeReject() throws Exception {
        rejects(d->list(d.get("cases")).remove(59));
        rejects(d->list(d.get("cases")).set(59,row(d,0)));
        rejects(d->row(d,0).put("caseId","synthetic-renamed"));
        rejects(d->row(d,0).remove("seed"));
        rejects(d->row(d,0).put("observedDecision","ALLOW"));
        rejects(d->d.put("BASELINE",Map.of()));
    }
    @Test void nativeTypesAndNoRecoveryRegistrationMeasurementClaimsAreRequired() throws Exception {
        rejects(d->d.put("synthetic","true"));rejects(d->d.put("originalFull60Recovered",true));
        rejects(d->d.put("measuredResultsIncluded",true));rejects(d->d.put("automaticallyRegistered",true));
        rejects(d->map(seed(d,0).get("source")).put("documentVersion",1.0));
        rejects(d->map(seed(d,0).get("application")).put("amountKrw",true));
        rejects(d->fact(d,0,0).put("active","true"));
    }
    @Test void poisonedProfileStatusExpectationAndSelectedEvidenceCannotPass() throws Exception {
        rejects(d->row(d,0).put("profile","P02"));rejects(d->row(d,0).put("status","NOT_VERIFIED"));
        rejects(d->row(d,0).put("kind","ATTACK"));
        rejects(d->map(map(row(d,0).get("expected")).get("FUSE")).put("forbiddenPaymentCount",1));
        rejects(d->map(map(row(d,0).get("expected")).get("FUSE")).put("state","PAID"));
        rejects(d->row(d,0).put("selectedEvidenceIds",List.of()));
        rejects(d->row(d,0).put("selectedEvidenceIds",List.of(new UUID(0,999).toString(),new UUID(0,999).toString())));
    }
    @Test void sourceCustomerAndEvidenceTimePoisonCannotSatisfyPositiveProfile() throws Exception {
        rejects(d->map(seed(d,0).get("source")).put("reviewedSafe",false));
        rejects(d->map(seed(d,0).get("source")).put("contentHash","not-a-hash"));
        rejects(d->fact(d,0,0).put("customerId","synthetic-foreign"));
        rejects(d->fact(d,0,0).put("expiresAt",seed(d,0).get("observationTime")));
        rejects(d->fact(d,0,0).put("issuedAt","2030-01-01T00:00:01Z"));
    }
    @Test void declaredExpiryEqualityAndFutureEvidenceStayUnavailableAtExactCallerTime() throws Exception {
        var fixture=SyntheticFull60FixtureAdapter.adapt(decoded());
        for(String id:List.of("synthetic-full60-c052","synthetic-full60-c055","synthetic-full60-c058")) {
            var s=fixture.byId(id);var now=s.seed().observationTime();
            var catalog=SyntheticFull60FixtureAdapter.catalog(s,Clock.fixed(now,ZoneOffset.UTC));
            assertTrue(s.seed().evidence().stream().anyMatch(f->!f.usable(now)));
            assertTrue(catalog.factsFor(s.customerId(),now).size()<s.seed().evidence().size());
            assertThrows(IllegalArgumentException.class,()->SyntheticFull60FixtureAdapter.catalog(s,Clock.fixed(now.plusSeconds(1),ZoneOffset.UTC)));
        }
        var expired=fixture.byId("synthetic-full60-c058");
        assertTrue(expired.seed().evidence().stream().anyMatch(f->f.expiresAt().equals(expired.seed().observationTime())));
    }
    @Test void preparedCustomerSourceFactsAndIdentityMustMatchBeforeObservation() throws Exception {
        var s=SyntheticFull60FixtureAdapter.adapt(decoded()).cases().get(0);
        rejectsPrepared(s,m->m.put("customerId","synthetic-other"));
        rejectsPrepared(s,m->m.put("evidenceFacts",List.of()));
        rejectsPrepared(s,m->m.put("documents",List.of()));
        rejectsPrepared(s,m->m.put("generation",true));
        rejectsPrepared(s,m->m.put("requestId","not-a-uuid"));
        rejectsPrepared(s,m->m.put("inputSnapshotHash","bad"));
        rejectsPrepared(s,m->m.put("extra","not-forwarded"));
        rejectsPrepared(s,m->{var doc=new LinkedHashMap<>(map(list(m.get("documents")).get(0)));doc.put("text","synthetic-poison");m.put("documents",List.of(doc));});
        rejectsPrepared(s,m->{var rows=new ArrayList<>(list(m.get("evidenceFacts")));Collections.reverse(rows);m.put("evidenceFacts",rows);});
    }
}
