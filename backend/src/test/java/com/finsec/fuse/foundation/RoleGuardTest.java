package com.finsec.fuse.foundation;

import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.auth.RoleGuard;
import com.finsec.fuse.common.ApiException;
import java.util.Set;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RoleGuardTest {
    @Test void customerCanOnlySeeItsOwnRegisteredScope() {
        Actor customer=new Actor("customer-101","CUSTOMER",Set.of("customer-101"));
        assertDoesNotThrow(()->RoleGuard.requireCustomer(customer,"customer-101"));
        ApiException error=assertThrows(ApiException.class,()->RoleGuard.requireCustomer(customer,"customer-102"));
        assertEquals(403,error.status());
        assertThrows(ApiException.class,()->RoleGuard.require(customer,"LOAN_REVIEWER"));
    }
    @Test void securityRoleDoesNotInheritStaffApproval() {
        Actor security=new Actor("security-01","SECURITY_OPERATOR",Set.of("customer-102"));
        assertDoesNotThrow(()->RoleGuard.require(security,"SECURITY_OPERATOR"));
        assertThrows(ApiException.class,()->RoleGuard.require(security,"LOAN_REVIEWER"));
    }
    @Test void actorScopeCannotBeMutatedByCallers() {
        var scope=new java.util.HashSet<>(Set.of("customer-101"));
        Actor actor=new Actor("customer-101","CUSTOMER",scope);scope.add("customer-102");
        assertFalse(actor.canAccess("customer-102"));
    }
}
