package com.finsec.fuse.persistence;

import com.finsec.fuse.common.ApiException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.SQLErrorCodeSQLExceptionTranslator;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Repository
public class Db {
    private final JdbcTemplate jdbc;
    public Db(JdbcTemplate jdbc) {
        // PostgreSQL 55P03 is not classified by Spring's default subclass translator.
        // Keep actual lock timeouts in the existing bounded, rollback-only retry category.
        jdbc.setExceptionTranslator(new SQLErrorCodeSQLExceptionTranslator("PostgreSQL"));
        this.jdbc=jdbc;
    }
    public JdbcTemplate jdbc() { return jdbc; }
    public int update(String sql,Object... args) { return jdbc.update(sql,bind(args)); }
    public List<Map<String,Object>> query(String sql,Object... args) { return jdbc.queryForList(sql,bind(args)); }
    public Optional<Map<String,Object>> one(String sql,Object... args) {
        var rows=query(sql,args);
        if(rows.size()>1) throw new IllegalStateException("Expected at most one database row");
        return rows.stream().findFirst();
    }
    public Map<String,Object> required(String sql,Object... args) {
        return one(sql,args).orElseThrow(()->new ApiException(404,"NOT_FOUND","Requested resource was not found"));
    }
    public void gate() {
        if(!TransactionSynchronizationManager.isActualTransactionActive())
            throw new IllegalStateException("Execution gate requires an active transaction");
        required("SELECT id,epoch FROM execution_gate WHERE id=1 FOR UPDATE");
    }
    public Map<String,Object> lockWorkflow(UUID workflowId) {
        return required("SELECT * FROM workflow WHERE id=? FOR UPDATE",workflowId);
    }
    public static UUID uuid(Map<String,Object> row,String key) {
        Object value=row.get(key); return value==null?null:value instanceof UUID u?u:UUID.fromString(value.toString());
    }
    public static int integer(Map<String,Object> row,String key) { return ((Number)row.get(key)).intValue(); }
    public static long number(Map<String,Object> row,String key) { return ((Number)row.get(key)).longValue(); }
    public static String string(Map<String,Object> row,String key) { Object v=row.get(key); return v==null?null:v.toString(); }
    public static Instant instant(Map<String,Object> row,String key) {
        Object v=row.get(key); if(v==null)return null;
        if(v instanceof Timestamp t)return t.toInstant();
        if(v instanceof java.time.OffsetDateTime t)return t.toInstant();
        return v instanceof Instant t?t:Instant.parse(v.toString());
    }
    private static Object[] bind(Object[] args) {
        Object[] bound=args.clone();
        for(int i=0;i<bound.length;i++) {
            if(bound[i] instanceof Instant instant) bound[i]=Timestamp.from(instant);
            else if(bound[i] instanceof Enum<?> value) bound[i]=value.name();
        }
        return bound;
    }
}
