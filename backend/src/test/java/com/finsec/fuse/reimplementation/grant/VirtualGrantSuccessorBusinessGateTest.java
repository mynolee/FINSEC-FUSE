package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.auth.GrantStorageShape.AllowedAction;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantStageBinding.BusinessConclusion;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.GrantStageTransactionServiceTest.*;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static org.junit.jupiter.api.Assertions.*;

/** Stored business eligibility in detached synthetic transactions, never real authority. */
final class VirtualGrantSuccessorBusinessGateTest {
    private static final class ParentCase {
        final Fixture f = new Fixture();
        final GrantSnapshot parent, child;
        final StageCommand consumption;
        final Receipt receipt;
        ParentCase(boolean loanParent, BusinessConclusion business) {
            if (loanParent) {
                assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS, f.complete().status());
                parent = f.child(40, AllowedAction.CREATE_LOAN_RECOMMENDATION);
                assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,
                        f.service.issueSuccessor(f.context, command(50,parent),f.root.grantId(),parent).status());
                consumption = command(51,parent);
                child = f.child(60,AllowedAction.EXECUTE_MOCK_PAYMENT);
            } else {
                parent=f.root; consumption=f.command;
                child=f.child(40,AllowedAction.CREATE_LOAN_RECOMMENDATION);
            }
            var evaluated=f.service.completeStage(f.context,consumption,prepared(100,business));
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,evaluated.status());
            assertNotNull(evaluated.receipt()); receipt=evaluated.receipt();
            assertEquals(business,receipt.result().businessConclusion());
            assertFalse(evaluated.actualAuthority()); assertFalse(evaluated.durable());
            assertEquals(Gate.CLEAR,f.facts.gate); assertEquals(Gate.CLEAR,f.facts.issuance);
        }
    }
    private static void negativeParent(boolean loanParent) {
        var p=new ParentCase(loanParent,BusinessConclusion.NEGATIVE); var f=p.f;
        var before=f.store.snapshot(); int initialIssuances=f.facts.issuances, resolutions=f.facts.resolutions;
        // Child identity, adjacency and scope are valid; an equally supplied positive parent succeeds below.
        for(long request:List.of(200L,201L)) {
            var rejected=f.service.issueSuccessor(f.context,command(request,p.child),p.parent.grantId(),p.child);
            assertEquals(Status.REFUSED_BEFORE_ADMISSION,rejected.status()); assertNull(rejected.receipt());
            assertEquals(before,f.store.snapshot());
            assertFalse(f.store.snapshot().get("virtual_grant_profile_grants").containsKey(p.child.grantId().toString()));
            assertFalse(f.store.snapshot().getOrDefault("virtual_grant_profile_successors",Map.of()).containsKey(p.parent.grantId().toString()));
            assertFalse(f.store.snapshot().get(ActionJournal.TABLE).containsKey(id(request).toString()));
        }
        assertEquals(initialIssuances+2,f.facts.issuances); assertEquals(resolutions,f.facts.resolutions);
        var replay=f.service.completeStage(f.context,p.consumption,null);
        assertEquals(Status.VIRTUAL_REPLAYED_IN_PROCESS,replay.status()); assertEquals(p.receipt,replay.receipt());
        assertEquals(BusinessConclusion.NEGATIVE,replay.receipt().result().businessConclusion());
        assertEquals(before,f.store.snapshot());
        // Rejection did not poison a global UUID or install an uncertainty barrier.
        var ordinary=new ActionJournal(f.store).execute("synthetic-other-actor",id(200),"synthetic-unrelated-operation",
                "d".repeat(64),tx->Map.of("requestId",id(200).toString(),"synthetic","independent-command"));
        assertEquals("independent-command",ordinary.get("synthetic"));
        assertEquals(before.get("virtual_grant_profile_results"),f.store.snapshot().get("virtual_grant_profile_results"));
        assertEquals(before.get("virtual_grant_profile_grants"),f.store.snapshot().get("virtual_grant_profile_grants"));
    }
    private static void positiveParent(boolean loanParent) {
        // Independently evaluates POSITIVE; never edits a consumed NEGATIVE receipt/result row.
        var p=new ParentCase(loanParent,BusinessConclusion.POSITIVE); var f=p.f;
        int count=f.store.snapshot().get("virtual_grant_profile_grants").size();
        var created=f.service.issueSuccessor(f.context,command(200,p.child),p.parent.grantId(),p.child);
        assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,created.status());
        assertEquals(count+1,f.store.snapshot().get("virtual_grant_profile_grants").size());
        assertEquals(p.child.grantId().toString(),f.store.snapshot().get("virtual_grant_profile_successors")
                .get(p.parent.grantId().toString()).get("childGrantId"));
        assertFalse(created.actualAuthority()); assertFalse(created.durable());
    }

    @Test void consumedNegativeKycIsReplayableButCannotIssueLoanUnderPermissiveOtherGate() { negativeParent(false); }
    @Test void consumedNegativeLoanIsReplayableButCannotIssuePaymentUnderPermissiveOtherGate() { negativeParent(true); }
    @Test void independentlyPositiveKycStillAllowsOtherwiseValidExplicitLoanChild() { positiveParent(false); }
    @Test void independentlyPositiveLoanStillAllowsOtherwiseValidExplicitPaymentChild() { positiveParent(true); }

    @Test void positiveStoredBusinessConclusionDoesNotOverrideAnotherIssuanceGate() {
        var p=new ParentCase(false,BusinessConclusion.POSITIVE); var f=p.f;
        for(Gate gate:List.of(Gate.REFUSED,Gate.UNKNOWN)) {
            f.facts.issuance=gate; var before=f.store.snapshot();
            var rejected=f.service.issueSuccessor(f.context,command(200,p.child),p.parent.grantId(),p.child);
            assertEquals(gate==Gate.REFUSED?Status.REFUSED_BEFORE_ADMISSION:Status.UNCONFIRMED_BEFORE_ADMISSION,rejected.status());
            assertNull(rejected.receipt()); assertEquals(before,f.store.snapshot());
        }
    }
}
