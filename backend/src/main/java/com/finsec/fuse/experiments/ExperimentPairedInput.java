package com.finsec.fuse.experiments;

import com.finsec.fuse.common.Json;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.workflow.KycContract;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Comparison provenance only. A matching digest never authorizes a workflow action. */
public final class ExperimentPairedInput {
    public static final String VERSION="FUSE-PAIRED-INPUT-1";
    public static final String REPORT_VERSION="FUSE-EVALUATION-2";
    private static final List<String> FIXTURE_FIELDS=List.of("caseId","kind","family","split","customerId","amountKrw",
        "payoutAccountId","documentVersion","evidenceVariant","mockReviewer","injection","forbiddenGoal");
    private ExperimentPairedInput() {}
    public record Prepared(KycContract.Input input,Map<String,Object> business) {
        public Prepared { business=Collections.unmodifiableMap(new LinkedHashMap<>(business)); }
    }
    /** Select actual seeded business facts, excluding generated application/workflow identifiers. */
    public static Prepared prepare(Db db,KycContract.Input input) {
        var facts=db.required("SELECT a.business_reference,a.customer_id,a.amount_krw,a.payout_account_id,"+
            "p.monthly_income_krw,p.max_loan_amount_krw,p.profile_hash,p.policy_version AS loan_policy_version,"+
            "m.customer_id AS account_customer_id,m.status AS account_status FROM workflow w "+
            "JOIN loan_application a ON a.id=w.application_id JOIN mock_profile p ON p.customer_id=a.customer_id "+
            "JOIN mock_account m ON m.id=a.payout_account_id WHERE w.id=?",input.workflowId());
        return new Prepared(input,facts);
    }
    /** Explicit field projection avoids accidentally hashing transport IDs or a supplied digest. */
    public static Map<String,Object> canonical(Json json,Map<String,Object> fixture,String fixtureHash,Prepared prepared,
                                               String modelMode,String model,String promptVersion,String promptHash) {
        var input=prepared.input();
        if(!json.hash(input.unhashed()).equals(input.inputSnapshotHash()))throw new IllegalArgumentException("Invalid input snapshot");
        var fixtureFields=new LinkedHashMap<String,Object>();
        for(String field:FIXTURE_FIELDS)fixtureFields.put(field,fixture.get(field));
        var documents=new ArrayList<Map<String,Object>>();
        for(var document:input.documents()) {
            String actual=Json.sha256(document.text().getBytes(StandardCharsets.UTF_8));
            if(!actual.equals(document.contentHash()))throw new IllegalArgumentException("Invalid document bytes");
            documents.add(Json.ordered("documentId",document.documentId(),"documentVersion",document.documentVersion(),"contentHash",actual));
        }
        return Json.ordered("version",VERSION,"fixtureHash",fixtureHash,"fixture",fixtureFields,
            "business",prepared.business(),"customerId",input.customerId(),"policyVersion",input.policyVersion(),
            "evidenceFacts",input.evidenceFacts(),"documents",documents,"modelMode",modelMode,"model",model,
            "promptVersion",promptVersion,"promptHash",promptHash,"mockReviewerVersion","MOCK-REVIEWER-1");
    }
    public static String hash(Json json,Map<String,Object> fixture,String fixtureHash,Prepared prepared,
                              String modelMode,String model,String promptVersion,String promptHash) {
        // Round-trip records to maps before recursively sorting every object key.
        return json.hash(ExperimentRegistry.sorted(json.map(json.write(canonical(json,fixture,fixtureHash,prepared,modelMode,model,promptVersion,promptHash)))));
    }
    public static String exclusion(Collection<Map<String,Object>> rows) {
        for(var row:rows) {
            if(!VERSION.equals(row.get("pairedInputVersion")))return row.get("pairedInputVersion")==null?"PAIRED_INPUT_MISSING":"PAIRED_INPUT_VERSION_UNSUPPORTED";
            if(!(row.get("pairedInputHash") instanceof String hash) || !hash.matches("[0-9a-f]{64}"))return "PAIRED_INPUT_MISSING";
            for(String binding:List.of("inputSnapshotHash","responseByteHash"))
                if(!(row.get(binding) instanceof String digest) || !digest.matches("[0-9a-f]{64}"))return "ARM_BINDING_MISSING";
            if(row.get("trace") instanceof Map<?,?> trace && trace.get("expectedPairedInputHash")!=null &&
                !row.get("pairedInputHash").equals(trace.get("expectedPairedInputHash")))return "UNPAIRED_INPUT";
        }
        return rows.stream().map(row->row.get("pairedInputHash")).distinct().count()==1?null:"UNPAIRED_INPUT";
    }
}
