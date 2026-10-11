package com.finsec.fuse.config;

import java.util.UUID;
import org.springframework.context.annotation.Configuration;
import org.springframework.format.FormatterRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** Keep path, header and query UUIDs consistent with strict JSON UUID values. */
@Configuration
public class PublicUuidConfiguration implements WebMvcConfigurer {
    @Override public void addFormatters(FormatterRegistry registry) {
        registry.addConverter(String.class,UUID.class,PublicUuidConfiguration::parseCanonical);
    }
    public static UUID parseCanonical(String value) {
        if(value==null || !value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
            throw new IllegalArgumentException("UUID must be a canonical lowercase string");
        return UUID.fromString(value);
    }
}
