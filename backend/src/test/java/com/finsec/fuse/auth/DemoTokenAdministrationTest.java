package com.finsec.fuse.auth;

import java.lang.reflect.Proxy;
import java.sql.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DemoTokenAdministrationTest {
    @Test void failedRollbackNeverEnablesAutoCommitOrReusesTheConnection() {
        List<String> calls=new ArrayList<>();
        Statement statement=(Statement)Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{Statement.class},(proxy,method,args)->{
            if(method.getName().equals("execute"))throw new SQLException("synthetic operation failure");
            return defaultValue(method.getReturnType());
        });
        Connection connection=(Connection)Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{Connection.class},(proxy,method,args)->{
            calls.add(method.getName()+(args==null?"":Arrays.toString(args)));
            return switch(method.getName()) {
                case "getAutoCommit" -> true;
                case "getTransactionIsolation" -> Connection.TRANSACTION_READ_COMMITTED;
                case "createStatement" -> statement;
                case "rollback" -> throw new SQLException("synthetic rollback failure");
                default -> defaultValue(method.getReturnType());
            };
        });
        SQLException failure=assertThrows(SQLException.class,()->DemoTokenAdministration.revokeActor(connection,"synthetic-actor"));
        assertTrue(calls.contains("rollback"));assertTrue(calls.contains("close"));assertFalse(calls.contains("setAutoCommit[true]"));assertFalse(calls.contains("commit"));
        assertFalse(failure.getMessage().contains("synthetic operation"));assertNull(failure.getCause());
    }
    @Test void uncertainCommitIsNotRetriedOrReportedAsSuccess()throws Exception {
        Connection connection=org.mockito.Mockito.mock(Connection.class);
        Statement statement=org.mockito.Mockito.mock(Statement.class);
        PreparedStatement insert=org.mockito.Mockito.mock(PreparedStatement.class);
        ResultSet marker=org.mockito.Mockito.mock(ResultSet.class);
        Array scope=org.mockito.Mockito.mock(Array.class);
        org.mockito.Mockito.when(connection.getAutoCommit()).thenReturn(true);
        org.mockito.Mockito.when(connection.getTransactionIsolation()).thenReturn(Connection.TRANSACTION_READ_COMMITTED);
        org.mockito.Mockito.when(connection.createStatement()).thenReturn(statement);
        org.mockito.Mockito.when(statement.executeQuery(org.mockito.ArgumentMatchers.anyString())).thenReturn(marker);
        org.mockito.Mockito.when(marker.next()).thenReturn(true,false);
        org.mockito.Mockito.when(marker.getInt("id")).thenReturn(1);org.mockito.Mockito.when(marker.getInt("format_version")).thenReturn(1);
        org.mockito.Mockito.when(marker.getTimestamp("initialized_at")).thenReturn(Timestamp.from(java.time.Instant.EPOCH));
        org.mockito.Mockito.when(marker.getObject("registry_id",UUID.class)).thenReturn(UUID.fromString("00000000-0000-4000-8000-000000000001"));
        org.mockito.Mockito.when(connection.createArrayOf(org.mockito.ArgumentMatchers.eq("text"),org.mockito.ArgumentMatchers.any(Object[].class))).thenReturn(scope);
        org.mockito.Mockito.when(connection.prepareStatement(org.mockito.ArgumentMatchers.anyString())).thenReturn(insert);
        org.mockito.Mockito.when(insert.executeUpdate()).thenReturn(1);
        org.mockito.Mockito.doThrow(new SQLException("synthetic uncertain transport")).when(connection).commit();
        var binding=new DemoTokenStore.Binding("a".repeat(64),new Actor("synthetic","CUSTOMER",Set.of("customer-101")));
        SQLException failure=assertThrows(SQLException.class,()->DemoTokenAdministration.issue(connection,binding,Set.of()));
        org.mockito.Mockito.verify(connection,org.mockito.Mockito.times(1)).commit();org.mockito.Mockito.verify(connection).rollback();
        org.mockito.Mockito.verify(insert,org.mockito.Mockito.times(1)).executeUpdate();
        assertNull(failure.getCause());assertFalse(failure.getMessage().contains("synthetic uncertain transport"));
    }
    @Test void administrativeHelpersAreNotSpringBeansAndHaveNoRawTokenParameters() {
        assertEquals(0,DemoTokenAdministration.class.getAnnotations().length);
        for(var method:DemoTokenStore.class.getDeclaredMethods())assertFalse(Set.of("initialize","issue","revoke","updateScope").contains(method.getName()));
    }
    private static Object defaultValue(Class<?> type) {
        if(type==boolean.class)return false;if(type==int.class)return 0;if(type==long.class)return 0L;return null;
    }
}
