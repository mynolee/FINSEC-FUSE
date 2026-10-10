package com.finsec.fuse.auth;

import java.sql.*;
import java.time.Instant;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.jdbc.datasource.DataSourceUtils;

/** No admission cache or writes; a separate READ COMMITTED statement supplies time and all bindings. */
@Repository
public final class JdbcDemoTokenStore implements DemoTokenStore {
    private final javax.sql.DataSource source;
    public JdbcDemoTokenStore(JdbcTemplate jdbc) { source=Objects.requireNonNull(jdbc.getDataSource()); }
    @Override public Snapshot lookup(String fingerprint,List<Binding> configured) {
        try {
            var requested=new LinkedHashSet<String>();
            for(var binding:configured)requested.add(binding.fingerprint());
            if(fingerprint!=null){DemoTokenStore.validateFingerprint(fingerprint);requested.add(fingerprint);}
            String match=requested.isEmpty()?"FALSE":"t.fingerprint IN ("+String.join(",",Collections.nCopies(requested.size(),"?"))+")";
            String sql="SELECT statement_timestamp() AS authority_time,r.id,r.registry_id,r.format_version,r.initialized_at,"+
                "t.fingerprint,t.registry_id AS token_registry_id,t.actor_id,t.role,t.initial_scope,t.current_scope,"+
                "t.issued_at,t.expires_at,t.security_policy,t.issuance_ttl_seconds,t.status,t.revoked_at,t.revision "+
                "FROM demo_auth_registry r LEFT JOIN demo_token t ON "+match;
            // READ COMMITTED obtains a fresh statement snapshot, including readiness within a transaction.
            // Reuse a bound connection rather than exhausting the pool with nested readiness checkouts.
            Connection c=DataSourceUtils.getConnection(source);
            try {
                if(c.getTransactionIsolation()!=Connection.TRANSACTION_READ_COMMITTED)throw new Unavailable();
                try(PreparedStatement p=c.prepareStatement(sql)) {
                    p.setQueryTimeout(5);int index=1;
                    for(String value:requested)p.setBytes(index++,HexFormat.of().parseHex(value));
                    try(ResultSet rs=p.executeQuery()) {
                        Map<String,Credential> records=new HashMap<>();Instant now=null;UUID registry=null;
                        while(rs.next()) {
                            UUID observed=rs.getObject("registry_id",UUID.class);
                            if(rs.getInt("id")!=1 || rs.getInt("format_version")!=1 || observed==null || rs.getTimestamp("initialized_at")==null
                                || (registry!=null&&!registry.equals(observed)))throw new Unavailable();
                            registry=observed;
                            Instant sampled=rs.getTimestamp("authority_time").toInstant();
                            if(now!=null&&!now.equals(sampled))throw new Unavailable();now=sampled;
                            byte[] digest=rs.getBytes("fingerprint");if(digest==null)continue;
                            if(!registry.equals(rs.getObject("token_registry_id",UUID.class)) || !"FUSE-SECURITY-1".equals(rs.getString("security_policy")) || rs.getInt("issuance_ttl_seconds")!=7200)throw new Unavailable();
                            var credential=new Credential(HexFormat.of().formatHex(digest),new Actor(rs.getString("actor_id"),rs.getString("role"),scope(rs,"initial_scope")),
                                scope(rs,"current_scope"),rs.getTimestamp("issued_at").toInstant(),rs.getTimestamp("expires_at").toInstant(),Status.valueOf(rs.getString("status")),instant(rs,"revoked_at"),rs.getLong("revision"));
                            if(records.put(credential.fingerprint(),credential)!=null)throw new Unavailable();
                        }
                        if(now==null||registry==null)throw new Unavailable();
                        for(var binding:configured) {
                            var record=records.get(binding.fingerprint());
                            if(record==null||!record.initialActor().equals(binding.actor()))throw new Unavailable();
                        }
                        return new Snapshot(now,fingerprint==null?null:records.get(fingerprint));
                    }
                }
            } finally {DataSourceUtils.releaseConnection(c,source);}
        } catch(SQLException|RuntimeException failure) { throw new Unavailable(); }
    }
    private static Instant instant(ResultSet rs,String column)throws SQLException {Timestamp value=rs.getTimestamp(column);return value==null?null:value.toInstant();}
    private static Set<String> scope(ResultSet rs,String column)throws SQLException {
        Array array=rs.getArray(column);if(array==null)throw new Unavailable();
        try {
            Object[] values=(Object[])array.getArray();var sorted=new TreeSet<String>();String previous=null;
            for(Object value:values) {
                if(!(value instanceof String text) || (previous!=null&&previous.compareTo(text)>=0))throw new Unavailable();
                sorted.add(text);previous=text;
            }
            return DemoTokenStore.canonicalScope(sorted);
        } finally {array.free();}
    }
}
