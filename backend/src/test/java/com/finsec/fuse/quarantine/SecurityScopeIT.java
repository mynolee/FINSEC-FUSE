package com.finsec.fuse.quarantine;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;
import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.payment.PaymentFixture;
import java.util.*;
import org.junit.jupiter.api.Test;

class SecurityScopeIT extends PaymentFixture {
    private static final Actor SCOPED=new Actor("restricted-security","SECURITY_OPERATOR",Set.of("customer-101"));
    @Test void securityRoleCannotApplyReadOrReleaseAnotherCustomersQuarantine() {
        UUID workflowId=ready102();UUID run=kycRun(workflowId);
        var request=new QuarantineRequest(QuarantineRequest.Scope.RUN,run,null,null,null,null,null,null,QuarantineRequest.Reason.SECURITY_INVESTIGATION,"Outside assigned scope");
        assertForbidden(()->quarantines.apply(SCOPED,UUID.randomUUID(),request));
        assertEquals(0,count("quarantine"));assertEquals("WAIT_APPROVAL",str(workflow(workflowId),"state"));
        var incident=quarantines.apply(SECURITY,UUID.randomUUID(),request);UUID quarantineId=(UUID)incident.get("quarantineId");
        assertForbidden(()->quarantines.impact(SCOPED,quarantineId));
        var ids=db.query("select id from trusted_evidence where customer_id='customer-102'").stream().map(r->uuid(r,"id")).toList();
        assertForbidden(()->quarantines.release(SCOPED,quarantineId,UUID.randomUUID(),new ReleaseRequest(new ReleaseRequest.Remediation(DOCUMENT,1,ids,null,null,"Unauthorized clearance"))));
        assertEquals("ACTIVE",str(db.required("select * from quarantine where id=?",quarantineId),"status"));
        assertForbidden(()->quarantines.impact(SCOPED,UUID.randomUUID()));
    }
    @Test void sourceAndAgentVersionScopesRequireEveryRegisteredPotentialCustomer() {
        UUID workflowId=start("customer-101");prepareKyc();
        // The safe document has registered consumers 102–104 even before their runs exist.
        assertForbidden(()->quarantines.apply(SCOPED,UUID.randomUUID(),new QuarantineRequest(QuarantineRequest.Scope.SOURCE_VERSION,null,null,null,DOCUMENT,1,null,null,QuarantineRequest.Reason.SOURCE_COMPROMISED,"Would affect unassigned customers")));
        assertForbidden(()->quarantines.apply(SCOPED,UUID.randomUUID(),new QuarantineRequest(QuarantineRequest.Scope.AGENT_VERSION,null,null,null,null,null,"KYC",1,QuarantineRequest.Reason.AGENT_COMPROMISED,"Would affect all customers")));
        var allowed=quarantines.apply(SCOPED,UUID.randomUUID(),new QuarantineRequest(QuarantineRequest.Scope.RUN,kycRun(workflowId),null,null,null,null,null,null,QuarantineRequest.Reason.SECURITY_INVESTIGATION,"Assigned customer only"));
        assertEquals("ACTIVE",allowed.get("state"));assertEquals(1,count("quarantine"));
    }
    @Test void previouslyAuthorizedReplayCannotDiscloseARestrictedIncidentAfterScopeChanges() {
        UUID workflowId=ready102();UUID action=UUID.randomUUID();
        var request=new QuarantineRequest(QuarantineRequest.Scope.WORKFLOW,null,null,workflowId,null,null,null,null,QuarantineRequest.Reason.SECURITY_INVESTIGATION,"Scope may narrow later");
        quarantines.apply(SECURITY,action,request);
        Actor narrowed=new Actor(SECURITY.actorId(),SECURITY.role(),Set.of("customer-101"));
        assertForbidden(()->quarantines.apply(narrowed,action,request));assertEquals(1,count("quarantine"));
    }
    private static void assertForbidden(Runnable action) {var ex=assertThrows(ApiException.class,action::run);assertEquals(403,ex.status());assertEquals("FORBIDDEN",ex.reasonCode());}
}
