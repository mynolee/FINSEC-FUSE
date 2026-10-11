package com.finsec.fuse.workflow;

import java.sql.Timestamp;
import java.time.*;
import java.util.*;

final class WorkflowValues {
    private WorkflowValues() {}
    static UUID id(Map<String,Object> row, String key) {
        Object v = row.get(key); return v == null ? null : v instanceof UUID u ? u : UUID.fromString(v.toString());
    }
    static String str(Map<String,Object> row, String key) { Object v=row.get(key); return v==null?null:v.toString(); }
    static int integer(Map<String,Object> row, String key) { return ((Number)row.get(key)).intValue(); }
    static long number(Map<String,Object> row, String key) { return ((Number)row.get(key)).longValue(); }
    static Instant instant(Map<String,Object> row, String key) {
        Object v=row.get(key); if(v==null)return null;
        if(v instanceof Instant i)return i; if(v instanceof Timestamp t)return t.toInstant();
        if(v instanceof OffsetDateTime d)return d.toInstant(); return Instant.parse(v.toString());
    }
    static String camel(String key) {
        StringBuilder b=new StringBuilder(); boolean upper=false;
        for(char c:key.toCharArray()){if(c=='_')upper=true;else {b.append(upper?Character.toUpperCase(c):c);upper=false;}}
        return b.toString();
    }
}
