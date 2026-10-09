package com.finsec.fuse.quarantine;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;
import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.payment.PaymentFixture;
import java.util.*;
import org.junit.jupiter.api.Test;

class QuarantineScopeIT extends PaymentFixture {
    @Test void sharedDocumentVersionBlocksOnlyItsRecordedConsumersAndCountsApplicationsOnce() {
        UUID bad=start("customer-101");var missing=prepareKyc();kyc.apply(missing,verified(missing));
        tx.executeWithoutResult(status->{db.gate();db.update("update application_registry set document_version=2 where customer_id='customer-102'");});
        UUID shared=ready102();UUID independent=start("customer-103");var safe=prepareKyc();kyc.apply(safe,verified(safe));
        var loan=jobs.claim().orElseThrow();loans.execute(loan.jobId(),loan.token());assertEquals("REJECTED",str(workflow(independent),"state"));
        var incident=quarantines.apply(SECURITY,UUID.randomUUID(),new QuarantineRequest(QuarantineRequest.Scope.SOURCE_VERSION,null,null,null,DOCUMENT,2,null,null,QuarantineRequest.Reason.SOURCE_COMPROMISED,"Shared source investigation"));
        assertEquals("BLOCKED",str(workflow(shared),"state"));assertEquals("REJECTED",str(workflow(independent),"state"));
        var impact=quarantines.impact(SECURITY,(UUID)incident.get("quarantineId"));var actual=(Map<?,?>)impact.get("actual");
        assertEquals(2,((Number)actual.get("workflowCount")).intValue());assertEquals(3,((Number)actual.get("runCount")).intValue());assertEquals(0,((Number)actual.get("paymentCount")).intValue());
        assertEquals(2000000L,((Number)actual.get("atRiskPendingAmountKrw")).longValue());
        assertEquals(Set.of(bad,shared),new HashSet<>((Collection<UUID>)impact.get("currentAffectedWorkflowIds")));
    }
    @Test void sourceReleaseRequiresEvidenceForEveryAffectedUnpaidCustomer() {
        UUID bad=start("customer-101");var missing=prepareKyc();kyc.apply(missing,verified(missing));
        tx.executeWithoutResult(status->{db.gate();db.update("update application_registry set document_version=2 where customer_id='customer-102'");});
        ready102();
        var incident=quarantines.apply(SECURITY,UUID.randomUUID(),new QuarantineRequest(QuarantineRequest.Scope.SOURCE_VERSION,null,null,null,DOCUMENT,2,null,null,QuarantineRequest.Reason.SOURCE_COMPROMISED,"Shared source investigation"));
        UUID incidentId=(UUID)incident.get("quarantineId");
        var ids102=db.query("select id from trusted_evidence where customer_id='customer-102'").stream().map(r->uuid(r,"id")).toList();
        var denied=assertThrows(ApiException.class,()->quarantines.release(SECURITY,incidentId,UUID.randomUUID(),new ReleaseRequest(new ReleaseRequest.Remediation(DOCUMENT,1,ids102,null,null,"Insufficient remediation"))));
        assertEquals("RECOVERY_CHECK_FAILED",denied.reasonCode());
        var all=new ArrayList<>(ids102);all.addAll(issueEvidence101());
        quarantines.release(SECURITY,incidentId,UUID.randomUUID(),new ReleaseRequest(new ReleaseRequest.Remediation(DOCUMENT,1,all,null,null,"Evidence covers every affected customer")));
        assertEquals("BLOCKED",str(workflow(bad),"state"));
        var stillBlocked=assertThrows(ApiException.class,()->recovery.resume(REVIEWER,bad,UUID.randomUUID(),new ResumeRequest(1,"Run quarantine still active")));
        assertEquals("QUARANTINED",stillBlocked.reasonCode());
    }
    @Test void repeatedActiveTargetReturnsSameIncidentWithoutDuplicateRows() {
        UUID id=start("customer-102");var prepared=prepareKyc();
        var request=new QuarantineRequest(QuarantineRequest.Scope.RUN,prepared.input().runId(),null,null,null,null,null,null,QuarantineRequest.Reason.SECURITY_INVESTIGATION,"Exact scope");
        var first=quarantines.apply(SECURITY,UUID.randomUUID(),request);var second=quarantines.apply(SECURITY,UUID.randomUUID(),request);
        assertEquals(first.get("quarantineId"),second.get("quarantineId"));assertEquals(1,count("quarantine"));assertRisk(id,10,0);
        var impact=quarantines.impact(SECURITY,(UUID)first.get("quarantineId"));
        assertEquals(1,((Number)((Map<?,?>)impact.get("actual")).get("runCount")).intValue());
        assertEquals(Set.of("LOAN","PAYMENT"),new HashSet<>((Collection<String>)((Map<?,?>)impact.get("potential")).get("roles")));
    }
}
