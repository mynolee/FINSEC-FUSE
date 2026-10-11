package com.finsec.fuse.common;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

/** Canonical callers supply ordered records/maps; no whitespace or platform encoding. */
@Component
public final class Json {
    private final JsonMapper mapper;
    public Json(JsonMapper mapper) { this.mapper = mapper; }
    public JsonMapper mapper() { return mapper; }
    public byte[] bytes(Object value) { return mapper.writeValueAsBytes(value); }
    public String write(Object value) { return new String(bytes(value), StandardCharsets.UTF_8); }
    public <T> T read(String value, Class<T> type) { return mapper.readValue(value, type); }
    public <T> T read(byte[] value, Class<T> type) { return mapper.readValue(value, type); }
    @SuppressWarnings("unchecked")
    public Map<String,Object> map(String value) { return mapper.readValue(value, LinkedHashMap.class); }
    public Map<String,Object> map(byte[] value) { return map(new String(value, StandardCharsets.UTF_8)); }
    public String hash(Object value) { return sha256(bytes(value)); }
    public static String sha256(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
    public static LinkedHashMap<String,Object> ordered(Object... keyValues) {
        if ((keyValues.length & 1) != 0) throw new IllegalArgumentException("Key/value pairs required");
        var result = new LinkedHashMap<String,Object>();
        for (int i=0; i<keyValues.length; i+=2) {
            String key = (String) keyValues[i];
            if (result.containsKey(key)) throw new IllegalArgumentException("Duplicate key: " + key);
            result.put(key,keyValues[i+1]);
        }
        return result;
    }
}
