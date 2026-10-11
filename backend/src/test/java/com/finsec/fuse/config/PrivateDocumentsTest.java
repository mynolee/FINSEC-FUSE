package com.finsec.fuse.config;

import com.finsec.fuse.common.Json;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.env.MockEnvironment;
import static org.junit.jupiter.api.Assertions.*;

class PrivateDocumentsTest {
    private final Json json=new Json(new JsonConfiguration().jsonMapper());
    @TempDir Path directory;
    private PrivateDocuments resolver(String file){return new PrivateDocuments(json,new MockEnvironment().withProperty("FUSE_PRIVATE_DOCUMENTS_PATH",file));}

    @Test void replayAndOfflineDoNotReadPrivateFiles() {
        for(String mode:List.of("replay","offline")) {
            var documents=new PrivateDocuments(json,new MockEnvironment().withProperty("fuse.kyc-mode",mode).withProperty("FUSE_PRIVATE_DOCUMENTS_PATH",directory.resolve("missing.json").toString()));
            assertFalse(documents.liveMode());assertEquals("FUSE_DOCUMENT_ID:seed-v1",documents.resolve("seed-v1",documents.liveMode()));
        }
    }
    @Test void livePreservesExactPrivateUtf8BytesAndRequiresExplicitId() throws Exception {
        Path file=directory.resolve("documents.json");Files.writeString(file,"{\"seed-v1\":\"  opaque-문서-01\\n\",\"rag-01\":\"opaque-02\"}");
        assertEquals("  opaque-문서-01\n",resolver(file.toString()).resolve("seed-v1",true));
        assertEquals("opaque-02",resolver(file.toString()).resolve("rag-01",true));
        assertThrows(PrivateDocuments.Unavailable.class,()->resolver(file.toString()).resolve("missing",true));
        assertTrue(new PrivateDocuments(json,new MockEnvironment().withProperty("FUSE_KYC_MODE","LIVE")).liveMode());
    }
    @Test void liveFailsClosedWithoutLeakingInvalidBodiesOrPaths() throws Exception {
        Path file=directory.resolve("private-file.json");
        for(String invalid:List.of("[]","null","{","{\"seed-v1\":null}","{\"seed-v1\":7}","{\"seed-v1\":\" \"}",
                "{\"seed-v1\":\"FUSE_DOCUMENT_ID:seed-v1\"}","{\"seed-v1\":\"opaque-01\",\"seed-v1\":\"opaque-02\"}",
                "{\"seed-v1\":\"opaque-01\"} {}","{\"seed-v1\":\""+"x".repeat(65_537)+"\"}","{\"seed-v1\":\""+"x".repeat(1024*1024)+"\"}")) {
            Files.writeString(file,invalid);
            var error=assertThrows(PrivateDocuments.Unavailable.class,()->resolver(file.toString()).resolve("seed-v1",true));
            assertTrue(error.getMessage().contains("FUSE_PRIVATE_DOCUMENTS_PATH"));assertFalse(error.getMessage().contains(file.toString()));assertNull(error.getCause());
        }
        assertThrows(PrivateDocuments.Unavailable.class,()->resolver("").resolve("seed-v1",true));
        assertThrows(PrivateDocuments.Unavailable.class,()->resolver(directory.resolve("absent.json").toString()).resolve("seed-v1",true));
        assertThrows(PrivateDocuments.Unavailable.class,()->resolver(file.toString()).resolve("../seed",false));
    }
    @Test void documentLimitCountsUtf8BytesAndInvalidUtf8IsRejected() throws Exception {
        Path file=directory.resolve("documents.json");String text="\uD83D\uDD39".repeat(4096);
        Files.writeString(file,json.write(java.util.Map.of("seed-v1",text)));
        assertEquals(text,resolver(file.toString()).resolve("seed-v1",true));
        Files.writeString(file,json.write(java.util.Map.of("seed-v1",text+"x")));
        assertThrows(PrivateDocuments.Unavailable.class,()->resolver(file.toString()).resolve("seed-v1",true));
        Files.write(file,new byte[]{'{','"','s','e','e','d','-','v','1','"',':','"',(byte)0xC3,(byte)0x28,'"','}'});
        assertThrows(PrivateDocuments.Unavailable.class,()->resolver(file.toString()).resolve("seed-v1",true));
    }
    @Test void rejectsLeafParentSymlinksTraversalAndNonregularFiles() throws Exception {
        Path file=directory.resolve("documents.json");Files.writeString(file,"{\"seed-v1\":\"opaque\"}");
        Path leaf=directory.resolve("linked.json");Files.createSymbolicLink(leaf,file);
        Path parent=directory.resolve("linked-parent");Files.createSymbolicLink(parent,directory);
        for(Path candidate:List.of(leaf,parent.resolve("documents.json"),directory.resolve("..").resolve(directory.getFileName()).resolve("documents.json"),directory))
            assertThrows(PrivateDocuments.Unavailable.class,()->resolver(candidate.toString()).resolve("seed-v1",true));
        assertEquals("opaque",resolver(file.toString()).resolve("seed-v1",true));
    }
    @Test void publicSeedContainsOnlyDocumentReferences() throws Exception {
        try(var stream=new ClassPathResource("fixtures/demo_seed.json").getInputStream()) {
            byte[] bytes=stream.readAllBytes();var fixture=json.read(bytes,DemoSeed.Fixture.class);
            assertEquals(List.of("seed-v1","seed-v2"),fixture.documents().stream().map(DemoSeed.Document::contentId).toList());
            assertFalse(new String(bytes,StandardCharsets.UTF_8).contains("\"content\""));
        }
    }
}
