package com.finsec.fuse.config;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.persistence.Db;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.env.MockEnvironment;
import static org.junit.jupiter.api.Assertions.*;

class DemoSeedTest {
    private final Json json=new Json(new JsonConfiguration().jsonMapper());
    @TempDir Path directory;
    private final DemoSeed.Fixture fixture=new DemoSeed.Fixture("test-fixture","test-policy",UUID.randomUUID(),
        List.of(new DemoSeed.Document(1,"seed-v1",true),new DemoSeed.Document(2,"seed-v2",false)),List.of());
    private static final class RecordingDb extends Db {
        final List<Object[]> documents=new ArrayList<>();
        RecordingDb(){super(new org.springframework.jdbc.core.JdbcTemplate());}
        @Override public void gate(){}
        @Override public int update(String sql,Object... args){if(sql.startsWith("INSERT INTO source_document_version"))documents.add(args);return 1;}
    }
    @Test void seedHashesResolvedBytesForBothReplayAndLive() throws Exception {
        Path file=directory.resolve("documents.json");Files.writeString(file,json.write(Map.of("seed-v1","opaque-문서-01\n","seed-v2","opaque-02")));
        for(String mode:List.of("replay","offline","live")) {
            var db=new RecordingDb();var resolver=new PrivateDocuments(json,new MockEnvironment().withProperty("fuse.kyc-mode",mode).withProperty("FUSE_PRIVATE_DOCUMENTS_PATH",file.toString()));
            new DemoSeed(db,json,()->Instant.EPOCH,null,resolver).seed(fixture);
            assertEquals(2,db.documents.size());
            for(int index=0;index<2;index++) {
                var row=db.documents.get(index);String expected=mode.equals("live")?(index==0?"opaque-문서-01\n":"opaque-02"):"FUSE_DOCUMENT_ID:seed-v"+(index+1);
                assertEquals(fixture.documentId(),row[0]);assertEquals(index+1,row[1]);assertEquals(expected,row[2]);
                assertEquals(Json.sha256(expected.getBytes(StandardCharsets.UTF_8)),row[3]);assertEquals(index==0,row[4]);
            }
        }
    }
    @Test void liveSeedNeverFallsBackWhenAssetsAreMissing() {
        var db=new RecordingDb();var resolver=new PrivateDocuments(json,new MockEnvironment().withProperty("fuse.kyc-mode","live"));
        assertThrows(PrivateDocuments.Unavailable.class,()->new DemoSeed(db,json,()->Instant.EPOCH,null,resolver).seed(fixture));
        assertTrue(db.documents.isEmpty());
    }
}
