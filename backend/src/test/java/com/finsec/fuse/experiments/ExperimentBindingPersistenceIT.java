package com.finsec.fuse.experiments;

import com.finsec.fuse.auth.Actor;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.persistence.ActionRequests;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.testing.FuseIntegrationTest;
import com.finsec.fuse.testing.PostgresSupport;
import com.finsec.fuse.workflow.KycContract;
import java.sql.DriverManager;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.env.MockEnvironment;
import static org.junit.jupiter.api.Assertions.*;

/** Actual async service persistence, separate ephemeral database, no external model/network. */
class ExperimentBindingPersistenceIT extends FuseIntegrationTest {
    @Autowired ActionRequests actions;
    @Autowired ExperimentRegistry registry;
    @Test @SuppressWarnings("unchecked") void serviceRetainsExactPrivateBytesAndExportsOnlyBoundDigests() throws Exception {
        String name="binding_"+UUID.randomUUID().toString().replace("-","");
        String central=PostgresSupport.url();String experiments=central.replaceFirst("/postgres(?=\\?|$)","/"+name);
        assertNotEquals(central,experiments);
        try(var connection=DriverManager.getConnection(central,"postgres","");var statement=connection.createStatement()) {
            statement.execute("CREATE DATABASE "+name);
        }
        var environment=new MockEnvironment().withProperty("spring.datasource.url",central)
            .withProperty("fuse.experiment-db-url",experiments).withProperty("fuse.experiment-db-username","postgres");
        var service=new ExperimentService(db,json,actions,registry,tx,environment,input->{throw new AssertionError("Replay cannot call a model");});
        try {
            var actor=new Actor("binding-test-developer","DEVELOPER",Set.of());
            var request=new ExperimentRequest("mvp-security-v1",List.of("T02_MISSING_EVIDENCE"),ExperimentRequest.Mode.PAIRED,ExperimentRequest.ModelMode.REPLAY,1);
            var accepted=tx.execute(status->service.start(actor,UUID.randomUUID(),request));
            UUID id=(UUID)accepted.get("experimentId");
            long deadline=System.nanoTime()+Duration.ofSeconds(60).toNanos();Map<String,Object> report;
            do {
                report=service.get(actor,id);
                if(Set.of("COMPLETED","FAILED","INTERRUPTED").contains(report.get("status")))break;
                Thread.sleep(20); // Observe completion only; no race ordering depends on this delay.
            }while(System.nanoTime()<deadline);
            assertEquals("COMPLETED",report.get("status"));assertEquals(ExperimentPairedInput.REPORT_VERSION,report.get("reportVersion"));
            var rows=(List<Map<String,Object>>)report.get("caseOutputs");assertEquals(2,rows.size());
            assertEquals(rows.getFirst().get("pairedInputHash"),rows.getLast().get("pairedInputHash"));
            assertNotEquals(rows.getFirst().get("inputSnapshotHash"),rows.getLast().get("inputSnapshotHash"));
            assertNotEquals(rows.getFirst().get("responseByteHash"),rows.getLast().get("responseByteHash"));
            var stored=db.query("SELECT b.*,r.environment FROM experiment_arm_binding b JOIN experiment_case_result r ON r.id=b.case_result_id WHERE r.experiment_id=?",id);
            assertEquals(2,stored.size());
            for(var binding:stored) {
                byte[] snapshot=(byte[])binding.get("input_bytes"),requestBytes=(byte[])binding.get("request_bytes"),responseBytes=(byte[])binding.get("response_bytes");
                assertEquals(Json.sha256(snapshot),binding.get("input_snapshot_hash"));
                assertEquals(Json.sha256(requestBytes),binding.get("request_byte_hash"));
                assertEquals(Json.sha256(responseBytes),binding.get("response_byte_hash"));
                var input=json.read(requestBytes,KycContract.Input.class);var response=json.read(responseBytes,KycContract.Response.class);
                assertTrue(response.boundTo(input));assertArrayEquals(json.bytes(input.unhashed()),snapshot);
                assertEquals(binding.get("request_id"),input.requestId());assertEquals(binding.get("run_id"),input.runId());
                var row=rows.stream().filter(r->r.get("environment").equals(binding.get("environment"))).findFirst().orElseThrow();
                var trace=(Map<String,Object>)row.get("trace");var links=(List<Map<String,Object>>)trace.get("armBindings");
                assertEquals(1,links.size());assertEquals(binding.get("id").toString(),links.getFirst().get("bindingId"));
                assertEquals(binding.get("response_byte_hash"),row.get("responseByteHash"));
            }
            String exported=json.write(report);
            for(String privateKey:List.of("inputBytes","requestBytes","responseBytes","input_bytes","request_bytes","response_bytes"))
                assertFalse(exported.contains("\""+privateKey+"\""));
            assertFalse(exported.contains("FUSE_DOCUMENT_ID:"),"Document bytes stay in private database records");
            assertEquals(1,((Map<String,Object>)report.get("metrics")).get("commonEligibleAttackPairs"));
            assertEquals(2,Db.integer(db.required("SELECT count(*) AS n FROM experiment_case_result WHERE experiment_id=?",id),"n"));
        }finally {
            service.close();
            try(var connection=DriverManager.getConnection(central,"postgres","");var statement=connection.createStatement()) {
                statement.execute("DROP DATABASE "+name+" WITH (FORCE)");
            }
        }
    }
}
