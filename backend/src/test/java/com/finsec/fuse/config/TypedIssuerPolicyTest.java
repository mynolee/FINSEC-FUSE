package com.finsec.fuse.config;

import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.io.ClassPathResource;
import static org.junit.jupiter.api.Assertions.*;

class TypedIssuerPolicyTest {
    @ParameterizedTest @ValueSource(strings={
            "null", "{}", "[]", "[\"mock-id-issuer\",\"mock-face-issuer\"]",
            "{\"ID_DOC\":[\"mock-id-issuer\"]}",
            "{\"ID_DOC\":[\"mock-id-issuer\"],\"FACE_MATCH\":[]}",
            "{\"ID_DOC\":[\"mock-id-issuer\"],\"FACE_MATCH\":null}",
            "{\"ID_DOC\":[\"mock-id-issuer\"],\"FACE_MATCH\":[null]}",
            "{\"ID_DOC\":[\"mock-id-issuer\"],\"FACE_MATCH\":[\" \"]}",
            "{\"ID_DOC\":[\"mock-id-issuer\"],\"FACE_MATCH\":[\"mock-face-issuer\"],\"UNKNOWN\":[\"issuer\"]}"})
    void invalidTypedRegistryFailsPolicyLoading(String invalid) throws Exception {
        var mapper=new JsonConfiguration().jsonMapper();
        try(var input=new ClassPathResource("config/demo_policy.json").getInputStream()) {
            var tree=mapper.readTree(input);((tools.jackson.databind.node.ObjectNode)tree).set("trustedIssuers",mapper.readTree(invalid));
            assertThrows(RuntimeException.class,()->mapper.treeToValue(tree,FusePolicy.class));
        }
    }
    @Test void missingTypedRegistryFailsPolicyLoading() throws Exception {
        var mapper=new JsonConfiguration().jsonMapper();
        try(var input=new ClassPathResource("config/demo_policy.json").getInputStream()) {
            var tree=mapper.readTree(input);((tools.jackson.databind.node.ObjectNode)tree).remove("trustedIssuers");
            assertThrows(RuntimeException.class,()->mapper.treeToValue(tree,FusePolicy.class));
        }
    }
    @Test void registryIsDeeplyImmutableAndRequiresExplicitAuthorityForEachKind() {
        var id=new HashSet<>(Set.of("id-only"));var source=new HashMap<String,Set<String>>();
        source.put("ID_DOC",id);source.put("FACE_MATCH",Set.of("face-only"));
        var registry=FusePolicy.validatedTrustedIssuers(source);id.add("face-only");source.clear();
        assertEquals(Set.of("id-only"),registry.get("ID_DOC"));
        assertThrows(UnsupportedOperationException.class,()->registry.put("OTHER",Set.of("issuer")));
        assertThrows(UnsupportedOperationException.class,()->registry.get("ID_DOC").add("other"));
    }
}
