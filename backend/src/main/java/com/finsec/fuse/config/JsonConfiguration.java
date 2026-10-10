package com.finsec.fuse.config;

import java.io.IOException;
import java.util.UUID;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.ValueDeserializer;
import tools.jackson.databind.module.SimpleModule;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.cfg.EnumFeature;
import tools.jackson.databind.cfg.CoercionAction;
import tools.jackson.databind.cfg.CoercionInputShape;
import tools.jackson.databind.type.LogicalType;
import tools.jackson.databind.json.JsonMapper;

@Configuration
public class JsonConfiguration {
    @Bean public JsonMapper jsonMapper() {
        SecurityPolicy limits;
        try { limits=loadSecurityPolicy(JsonMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build()); }
        catch(IOException failure) { throw new IllegalStateException("Security policy unavailable",failure); }
        return JsonMapper.builder(JsonFactory.builder().streamReadConstraints(
                StreamReadConstraints.builder().maxNestingDepth(limits.jsonMaxDepth()).maxStringLength(limits.publicRequestMaxBytes()).maxNumberLength(128).build()).build())
            .addModule(canonicalUuidModule())
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
            .enable(EnumFeature.FAIL_ON_NUMBERS_FOR_ENUMS)
            .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT)
            .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS)
            .disable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
            .withCoercionConfig(LogicalType.Textual,c -> c
                .setCoercion(CoercionInputShape.Integer,CoercionAction.Fail)
                .setCoercion(CoercionInputShape.Float,CoercionAction.Fail)
                .setCoercion(CoercionInputShape.Boolean,CoercionAction.Fail)).build();
    }
    private static SimpleModule canonicalUuidModule() {
        var module=new SimpleModule("fuse-canonical-uuid");
        module.addDeserializer(UUID.class,new ValueDeserializer<UUID>() {
            @Override public UUID deserialize(JsonParser parser,DeserializationContext context) {
                if(!parser.hasToken(JsonToken.VALUE_STRING))
                    return context.reportInputMismatch(UUID.class,"UUID must be a canonical lowercase string");
                String value=parser.getString();
                if(!value.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))
                    return context.reportInputMismatch(UUID.class,"UUID must be a canonical lowercase string");
                return UUID.fromString(value);
            }
        });
        return module;
    }
    @Bean public SecurityPolicy securityPolicy(JsonMapper mapper) throws IOException { return loadSecurityPolicy(mapper); }
    private SecurityPolicy loadSecurityPolicy(JsonMapper mapper) throws IOException {
        try (var in=new ClassPathResource("config/security_policy.json").getInputStream()) {
            return mapper.readValue(in,SecurityPolicy.class);
        }
    }
    @Bean public FusePolicy fusePolicy(JsonMapper mapper,org.springframework.core.env.Environment environment) throws IOException {
        FusePolicy policy=fusePolicy(mapper);
        String requested=environment.getProperty("FUSE_POLICY_VERSION",policy.policyVersion());
        if(!policy.policyVersion().equals(requested))
            throw new IllegalStateException("Configured policy version does not match the versioned policy file");
        return policy;
    }
    public FusePolicy fusePolicy(JsonMapper mapper) throws IOException {
        try(var in=new ClassPathResource("config/demo_policy.json").getInputStream()) {
            return mapper.readValue(in,FusePolicy.class);
        }
    }
}
