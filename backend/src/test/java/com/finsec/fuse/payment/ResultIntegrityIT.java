package com.finsec.fuse.payment;

import static com.finsec.fuse.payment.PaymentValues.*;
import static org.junit.jupiter.api.Assertions.*;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;

class ResultIntegrityIT extends PaymentFixture {
    @Test void bodyOnlyTamperingCannotChangeTheReviewedLoanWhileKeepingItsOldDigest() {
        UUID workflowId=ready102();var pay=approve(workflowId);UUID loanId=uuid(workflow(workflowId),"current_loan_result_id");
        var before=db.required("select * from agent_result where id=?",loanId);
        assertThrows(DataAccessException.class,()->tx.executeWithoutResult(status->{db.gate();db.lockWorkflow(workflowId);
            db.update("update agent_result set body_json=jsonb_set(body_json,'{recommendation}','\"REJECT_RECOMMENDED\"') where id=?",loanId);
        }));
        var after=db.required("select * from agent_result where id=?",loanId);
        assertEquals(str(before,"body_json"),str(after,"body_json"));assertEquals(str(before,"result_hash"),str(after,"result_hash"));
        assertEquals("APPROVE_RECOMMENDED",json.map(str(after,"body_json")).get("recommendation"));
        assertEquals("PAID",paymentAgent.execute(pay.jobId(),pay.token()).get("state"));assertEquals(1,count("mock_payment"));
    }
    @Test void invalidatedResultsCannotBeResurrectedOrReboundToNewEvidence() {
        UUID workflowId=ready102();UUID loanId=uuid(workflow(workflowId),"current_loan_result_id");
        quarantines.automaticRun(kycRun(workflowId),"SECURITY_INVESTIGATION","Preserve invalidation");
        assertEquals("INVALIDATED",str(db.required("select * from agent_result where id=?",loanId),"status"));
        assertThrows(DataAccessException.class,()->db.update("update agent_result set status='VALIDATED' where id=?",loanId));
        assertThrows(DataAccessException.class,()->db.update("update agent_result set evidence_bundle_hash=? where id=?","a".repeat(64),loanId));
        assertThrows(DataAccessException.class,()->db.update("update agent_result set result_hash=? where id=?","b".repeat(64),loanId));
        assertThrows(DataAccessException.class,()->db.update("delete from agent_result where id=?",loanId));
        assertEquals(0,count("mock_payment"));assertRisk(workflowId,35,0);
    }
}
