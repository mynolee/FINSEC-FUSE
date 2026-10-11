package com.finsec.fuse.auth;

import java.sql.*;
import java.util.*;

/** Explicit offline administration with an existing owner connection. Never a web component. */
public final class DemoTokenAdministration {
    private DemoTokenAdministration() {}
    @FunctionalInterface private interface Operation<T> { T run(Connection connection)throws SQLException; }
    public static void initialize(Connection connection,List<DemoTokenStore.Binding> bindings)throws SQLException {
        List<DemoTokenStore.Binding> checked=List.copyOf(bindings);distinct(checked);
        transaction(connection,c->{
            // This lock is schema-local. A second initializer waits, then observes the committed marker.
            try(Statement s=c.createStatement()) {s.execute("LOCK TABLE demo_auth_registry IN ACCESS EXCLUSIVE MODE");}
            try(Statement s=c.createStatement();ResultSet rs=s.executeQuery("SELECT (SELECT count(*) FROM demo_auth_registry)+(SELECT count(*) FROM demo_token)")) {
                rs.next();if(rs.getLong(1)!=0)throw new SQLException("Authentication ledger is already initialized","55000");
            }
            UUID registry=UUID.randomUUID();
            try(PreparedStatement p=c.prepareStatement("INSERT INTO demo_auth_registry(id,registry_id,format_version,initialized_at) VALUES(1,?,1,statement_timestamp())")) {
                p.setObject(1,registry);p.executeUpdate();
            }
            for(var binding:checked)insert(c,registry,binding);
            return null;
        });
    }
    public static void issue(Connection connection,DemoTokenStore.Binding binding,Set<String> replacementFingerprints)throws SQLException {
        var replacements=new TreeSet<String>(replacementFingerprints);replacements.forEach(DemoTokenStore::validateFingerprint);
        if(replacements.contains(binding.fingerprint()))throw new IllegalArgumentException("A replacement must be a fresh credential");
        transaction(connection,c->{
            UUID registry=lockRegistry(c);
            for(String fingerprint:replacements) {
                try(PreparedStatement p=c.prepareStatement("SELECT fingerprint FROM demo_token WHERE fingerprint=? FOR UPDATE")) {
                    p.setBytes(1,bytes(fingerprint));try(ResultSet rs=p.executeQuery()){if(!rs.next())throw new SQLException("Selected credential does not exist","55000");}
                }
            }
            insert(c,registry,binding);
            for(String fingerprint:replacements)revoke(c,"fingerprint=?",bytes(fingerprint));
            return null;
        });
    }
    public static int revokeActor(Connection connection,String actorId)throws SQLException {
        validateActorId(actorId);
        return transaction(connection,c->{lockRegistry(c);lockActor(c,actorId);return revoke(c,"actor_id=?",actorId);});
    }
    public static int revokeFingerprint(Connection connection,String fingerprint)throws SQLException {
        DemoTokenStore.validateFingerprint(fingerprint);
        return transaction(connection,c->{lockRegistry(c);return revoke(c,"fingerprint=?",bytes(fingerprint));});
    }
    public static int updateScope(Connection connection,String actorId,Set<String> customers)throws SQLException {
        validateActorId(actorId);var scope=DemoTokenStore.canonicalScope(customers);
        return transaction(connection,c->{
            lockRegistry(c);lockActor(c,actorId);
            Array values=c.createArrayOf("text",scope.toArray(String[]::new));
            try(PreparedStatement p=c.prepareStatement("UPDATE demo_token SET current_scope=?,revision=revision+1 WHERE actor_id=? AND current_scope IS DISTINCT FROM ?")) {
                p.setArray(1,values);p.setString(2,actorId);p.setArray(3,values);return p.executeUpdate();
            } finally {values.free();}
        });
    }
    private static void insert(Connection c,UUID registry,DemoTokenStore.Binding binding)throws SQLException {
        Array scope=c.createArrayOf("text",DemoTokenStore.canonicalScope(binding.actor().customerIds()).toArray(String[]::new));
        try(PreparedStatement p=c.prepareStatement("INSERT INTO demo_token(fingerprint,registry_id,actor_id,role,initial_scope,current_scope,issued_at,expires_at,security_policy,issuance_ttl_seconds,status,revoked_at,revision) "+
            "SELECT ?,?,?,?,?,?,now_time,now_time+interval '7200 seconds','FUSE-SECURITY-1',7200,'ACTIVE',NULL,0 FROM (SELECT statement_timestamp() AS now_time) authority")) {
            p.setBytes(1,bytes(binding.fingerprint()));p.setObject(2,registry);p.setString(3,binding.actor().actorId());p.setString(4,binding.actor().role());p.setArray(5,scope);p.setArray(6,scope);p.executeUpdate();
        } finally {scope.free();}
    }
    private static UUID lockRegistry(Connection c)throws SQLException {
        try(Statement s=c.createStatement();ResultSet rs=s.executeQuery("SELECT id,registry_id,format_version,initialized_at FROM demo_auth_registry FOR UPDATE")) {
            if(!rs.next()||rs.getInt("id")!=1||rs.getInt("format_version")!=1||rs.getTimestamp("initialized_at")==null)throw new SQLException("Authentication ledger is unavailable","55000");
            UUID registry=rs.getObject("registry_id",UUID.class);
            if(registry==null||rs.next())throw new SQLException("Authentication ledger is unavailable","55000");
            return registry;
        }
    }
    private static void lockActor(Connection c,String actorId)throws SQLException {
        try(PreparedStatement p=c.prepareStatement("SELECT fingerprint FROM demo_token WHERE actor_id=? ORDER BY fingerprint FOR UPDATE")) {
            p.setString(1,actorId);try(ResultSet rs=p.executeQuery()){while(rs.next()){ /* lock all selected rows before mutation */ }}
        }
    }
    private static int revoke(Connection c,String predicate,Object value)throws SQLException {
        try(PreparedStatement p=c.prepareStatement("UPDATE demo_token SET status='REVOKED',revoked_at=statement_timestamp(),revision=revision+1 WHERE "+predicate+" AND status='ACTIVE'")) {
            if(value instanceof byte[] digest)p.setBytes(1,digest);else p.setString(1,(String)value);
            return p.executeUpdate();
        }
    }
    private static <T> T transaction(Connection c,Operation<T> operation)throws SQLException {
        if(!c.getAutoCommit())throw new SQLException("Administration requires a separate owner connection","25001");
        int isolation=c.getTransactionIsolation();boolean completed=false;
        c.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);c.setAutoCommit(false);
        try {
            try(Statement s=c.createStatement()){s.execute("SET LOCAL lock_timeout='2s'");s.execute("SET LOCAL statement_timeout='5s'");}
            T result=operation.run(c);c.commit();completed=true;return result;
        } catch(SQLException|RuntimeException failure) {
            try{c.rollback();completed=true;}catch(SQLException ignored){ /* Never turn auto-commit on after an unconfirmed rollback. */ }
            throw new SQLException("Authentication administration failed; reconcile the operation before retrying","55000");
        } finally {
            if(completed) {
                try{c.setAutoCommit(true);c.setTransactionIsolation(isolation);}catch(SQLException resetFailure){throw new SQLException("Administration connection outcome requires reconciliation","55000");}
            } else {
                try{c.close();}catch(SQLException ignored){ /* The short-lived connection must not be reused. */ }
            }
        }
    }
    private static byte[] bytes(String fingerprint){return HexFormat.of().parseHex(fingerprint);}
    private static void validateActorId(String value) {
        if(value==null||!value.matches("[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}"))throw new IllegalArgumentException("Invalid credential identity");
    }
    private static void distinct(List<DemoTokenStore.Binding> bindings) {
        var seen=new HashSet<String>();for(var binding:bindings)if(!seen.add(binding.fingerprint()))throw new IllegalArgumentException("Duplicate credential binding");
    }
}
