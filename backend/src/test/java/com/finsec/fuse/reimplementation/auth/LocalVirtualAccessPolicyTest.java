package com.finsec.fuse.reimplementation.auth;

import com.finsec.fuse.reimplementation.simulation.SimulationAccess.Operation;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.auth.LocalVirtualAccessPolicy.Decision.*;

/** Selected local role/resource contract only, not a real role assignment or domain authorization. */
final class LocalVirtualAccessPolicyTest {
    private static final UUID PRINCIPAL=new UUID(0,1), WORKFLOW=new UUID(0,2), OTHER=new UUID(0,3);
    private LocalVirtualPrincipal principal(Set<TokenRegistryInput.Role> roles) {
        return new LocalVirtualPrincipal(PRINCIPAL,"synthetic-policy-actor",0,LocalVirtualPrincipal.Status.ACTIVE,
            roles,Set.of("synthetic-customer"),Map.of(WORKFLOW,"synthetic-customer"),2);
    }
    @Test void selectedSixByNineRoleTableIsExactAndNeverSuppliesResourceScope() {
        // Explicit selected policy table, independent of production switch structure.
        var allowed=new EnumMap<TokenRegistryInput.Role,Set<Operation>>(TokenRegistryInput.Role.class);
        allowed.put(TokenRegistryInput.Role.CUSTOMER,Set.of(Operation.READ,Operation.START,Operation.RESUME));
        allowed.put(TokenRegistryInput.Role.LOAN_REVIEWER,Set.of(Operation.READ,Operation.REVIEW));
        allowed.put(TokenRegistryInput.Role.SECURITY_OPERATOR,Set.of(Operation.READ,Operation.QUARANTINE,Operation.RELEASE));
        allowed.put(TokenRegistryInput.Role.DEVELOPER,Set.of(Operation.READ,Operation.EXPERIMENT));
        allowed.put(TokenRegistryInput.Role.KYC_SERVICE,Set.of(Operation.READ,Operation.KYC_OBSERVATION));
        allowed.put(TokenRegistryInput.Role.FUSE_WORKER,Set.of(Operation.READ,Operation.KYC_OBSERVATION,Operation.PAYMENT));
        assertEquals(6,TokenRegistryInput.Role.values().length);assertEquals(9,Operation.values().length);
        int checked=0;
        for(var role:TokenRegistryInput.Role.values())for(var operation:Operation.values()) {
            var p=principal(Set.of(role));boolean expected=allowed.get(role).contains(operation);
            assertEquals(expected,LocalVirtualAccessPolicy.roleAllows(p,operation),role+"/"+operation);
            assertEquals(expected?ALLOW:FORBIDDEN,LocalVirtualAccessPolicy.assess(p,operation,WORKFLOW,"synthetic-customer"));
            assertEquals(expected?SCOPE_UNCONFIRMED:FORBIDDEN,LocalVirtualAccessPolicy.assess(p,operation,null,null));checked++;
        }
        assertEquals(54,checked);
    }
    @Test void workflowAndCustomerAssignmentsAreExplicitAndNeverWildcardOrCrossJoined() {
        var p=principal(Set.of(TokenRegistryInput.Role.CUSTOMER));
        assertEquals(ALLOW,LocalVirtualAccessPolicy.assess(p,Operation.READ,WORKFLOW,null));
        assertEquals(ALLOW,LocalVirtualAccessPolicy.assess(p,Operation.START,null,"synthetic-customer"));
        assertEquals(FORBIDDEN,LocalVirtualAccessPolicy.assess(p,Operation.READ,OTHER,"synthetic-customer"));
        assertEquals(FORBIDDEN,LocalVirtualAccessPolicy.assess(p,Operation.READ,WORKFLOW,"synthetic-other"));
        assertEquals(FORBIDDEN,LocalVirtualAccessPolicy.assess(p,Operation.READ,null,"synthetic-other"));
        var empty=new LocalVirtualPrincipal(PRINCIPAL,"synthetic-policy-actor",0,LocalVirtualPrincipal.Status.ACTIVE,
            Set.of(TokenRegistryInput.Role.CUSTOMER),Set.of(),Map.of(),1);
        assertEquals(FORBIDDEN,LocalVirtualAccessPolicy.assess(empty,Operation.READ,WORKFLOW,null));
        assertEquals(SCOPE_UNCONFIRMED,LocalVirtualAccessPolicy.assess(empty,Operation.READ,null,null));
    }
    @Test void disabledUnknownEmptyRolesAndNullOperationNeverGrantRolePermission() {
        var p=principal(Set.of(TokenRegistryInput.Role.CUSTOMER));
        for(var status:List.of(LocalVirtualPrincipal.Status.DISABLED,LocalVirtualPrincipal.Status.UNCONFIRMED)) {
            var changed=new LocalVirtualPrincipal(p.principalId(),p.actorAlias(),p.bindingRevision(),status,p.roles(),
                p.customerAssignments(),p.workflowAssignments(),2);
            for(var op:Operation.values())assertEquals(FORBIDDEN,LocalVirtualAccessPolicy.assess(changed,op,WORKFLOW,null));
        }
        assertFalse(LocalVirtualAccessPolicy.roleAllows(null,Operation.READ));
        assertFalse(LocalVirtualAccessPolicy.roleAllows(p,null));
        assertFalse(LocalVirtualAccessPolicy.roleAllows(principal(Set.of()),Operation.READ));
    }
    @Test void principalSnapshotsCollectionsAndChecksExplicitBoundsWithoutParsingAliasAsUuid() {
        var roles=new HashSet<>(Set.of(TokenRegistryInput.Role.CUSTOMER));
        var customers=new HashSet<>(Set.of("synthetic-customer"));
        var workflows=new HashMap<>(Map.of(WORKFLOW,"synthetic-customer"));
        var p=new LocalVirtualPrincipal(PRINCIPAL,"synthetic-not-a-uuid",0,LocalVirtualPrincipal.Status.ACTIVE,
            roles,customers,workflows,2);
        roles.clear();customers.clear();workflows.clear();
        assertEquals(1,p.roles().size());assertEquals(1,p.customerAssignments().size());assertEquals(1,p.workflowAssignments().size());
        assertThrows(UnsupportedOperationException.class,()->p.roles().clear());
        assertThrows(UnsupportedOperationException.class,()->p.customerAssignments().clear());
        assertThrows(UnsupportedOperationException.class,()->p.workflowAssignments().clear());
        assertThrows(IllegalArgumentException.class,()->new LocalVirtualPrincipal(PRINCIPAL,p.actorAlias(),0,p.status(),p.roles(),p.customerAssignments(),p.workflowAssignments(),1));
        assertThrows(IllegalArgumentException.class,()->new LocalVirtualPrincipal(PRINCIPAL,p.actorAlias(),-1,p.status(),p.roles(),Set.of(),Map.of(),1));
        assertThrows(IllegalArgumentException.class,()->new LocalVirtualPrincipal(PRINCIPAL,"not-synthetic",0,p.status(),p.roles(),Set.of(),Map.of(),1));
        assertEquals("LocalVirtualPrincipal[REDACTED]",p.toString());
    }
}
