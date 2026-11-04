package com.finsec.fuse.reimplementation.auth;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static com.finsec.fuse.reimplementation.auth.TokenIssuanceOutcomeProjector.*;

/** Private synthetic source only: NOT_RUN, no IO, token material or workflow simulation. */
final class TokenIssuanceOutcomeProjectorTest {
    private Projection project(StorageEvidence storage, Delivery delivery, Cleanup cleanup) {
        Projection p = TokenIssuanceOutcomeProjector.project(new Input(storage, delivery, cleanup));
        assertSame(storage, p.storage());
        assertSame(delivery, p.delivery());
        assertSame(cleanup, p.cleanup());
        assertSame(CurrentRowState.UNKNOWN, p.currentRowState());
        assertFalse(p.automaticRetryAllowed());
        assertFalse(p.reissueAllowed());
        assertFalse(p.executionAuthorityGranted());
        return p;
    }

    @Test void confirmedCommitAndDeliveryDoNotProveCurrentActiveRow() {
        assertSame(Status.INSERT_AND_DELIVERY_CONFIRMED,
                project(StorageEvidence.INSERT_CONFIRMED, Delivery.COMPLETE, Cleanup.CONFIRMED).status());
    }

    @Test void failedAndUnknownDeliveryRetainConfirmedInsertWithoutAutomaticReplacement() {
        assertSame(Status.DELIVERY_UNCONFIRMED,
                project(StorageEvidence.INSERT_CONFIRMED, Delivery.FAILED, Cleanup.CONFIRMED).status());
        assertSame(Status.DELIVERY_UNCONFIRMED,
                project(StorageEvidence.INSERT_CONFIRMED, Delivery.UNKNOWN, Cleanup.CONFIRMED).status());
        assertSame(Status.INSERT_CONFIRMED_DELIVERY_NOT_ATTEMPTED,
                project(StorageEvidence.INSERT_CONFIRMED, Delivery.NOT_ATTEMPTED, Cleanup.CONFIRMED).status());
    }

    @Test void cleanupUnknownDoesNotEraseCommitOrDeliveryEvidence() {
        assertSame(Status.INSERT_AND_DELIVERY_CONFIRMED,
                project(StorageEvidence.INSERT_CONFIRMED, Delivery.COMPLETE, Cleanup.UNKNOWN).status());
        assertSame(Status.DELIVERY_UNCONFIRMED,
                project(StorageEvidence.INSERT_CONFIRMED, Delivery.FAILED, Cleanup.UNKNOWN).status());
    }

    @Test void uncertainCommitIsNotRollbackSuccessOrRetryPermission() {
        assertSame(Status.COMMIT_UNCONFIRMED,
                project(StorageEvidence.COMMIT_UNCONFIRMED, Delivery.NOT_ATTEMPTED, Cleanup.CONFIRMED).status());
        assertSame(Status.COMMIT_UNCONFIRMED,
                project(StorageEvidence.COMMIT_UNCONFIRMED, Delivery.NOT_ATTEMPTED, Cleanup.UNKNOWN).status());
    }

    @Test void explicitRollbackEvidenceIsPreservedSeparatelyFromUnclassifiedStorageFailure() {
        assertSame(Status.FAILED_ROLLED_BACK,
                project(StorageEvidence.ROLLBACK_CONFIRMED, Delivery.NOT_ATTEMPTED, Cleanup.CONFIRMED).status());
        assertSame(Status.FAILED_ROLLED_BACK,
                project(StorageEvidence.ROLLBACK_CONFIRMED, Delivery.NOT_ATTEMPTED, Cleanup.UNKNOWN).status());
        // STORAGE_UNAVAILABLE cannot be translated to rollback evidence by this projector.
        assertSame(Status.STORAGE_RESULT_UNKNOWN,
                project(StorageEvidence.STORAGE_FAILURE_UNCLASSIFIED, Delivery.NOT_ATTEMPTED, Cleanup.CONFIRMED).status());
    }

    @Test void noAttemptAndRefusalHaveNoWriteCleanupOrDeliveryClaim() {
        assertSame(Status.NOT_ISSUED,
                project(StorageEvidence.NOT_ATTEMPTED, Delivery.NOT_ATTEMPTED, Cleanup.NOT_APPLICABLE).status());
        assertSame(Status.REFUSED,
                project(StorageEvidence.REFUSED_BEFORE_WRITE, Delivery.NOT_ATTEMPTED, Cleanup.NOT_APPLICABLE).status());
    }

    @Test void contradictoryDeliveryEvidenceIsRefusedRatherThanProjectedAsIssued() {
        for (StorageEvidence storage : new StorageEvidence[] { StorageEvidence.COMMIT_UNCONFIRMED,
                StorageEvidence.ROLLBACK_CONFIRMED, StorageEvidence.NOT_ATTEMPTED,
                StorageEvidence.REFUSED_BEFORE_WRITE, StorageEvidence.STORAGE_FAILURE_UNCLASSIFIED }) {
            Cleanup cleanup = (storage == StorageEvidence.NOT_ATTEMPTED
                    || storage == StorageEvidence.REFUSED_BEFORE_WRITE) ? Cleanup.NOT_APPLICABLE : Cleanup.CONFIRMED;
            for (Delivery delivery : new Delivery[] { Delivery.COMPLETE, Delivery.FAILED, Delivery.UNKNOWN }) {
                IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                        () -> new Input(storage, delivery, cleanup));
                assertEquals("INVALID_TOKEN_ISSUANCE_OUTCOME", error.getMessage());
                assertNull(error.getCause());
            }
        }
    }

    @Test void nullUnknownInputsAndContradictoryCleanupFailClosed() {
        assertThrows(IllegalArgumentException.class, () -> TokenIssuanceOutcomeProjector.project(null));
        assertThrows(IllegalArgumentException.class, () -> new Input(null, Delivery.NOT_ATTEMPTED, Cleanup.NOT_APPLICABLE));
        assertThrows(IllegalArgumentException.class, () -> new Input(StorageEvidence.INSERT_CONFIRMED, null, Cleanup.CONFIRMED));
        assertThrows(IllegalArgumentException.class, () -> new Input(StorageEvidence.INSERT_CONFIRMED, Delivery.COMPLETE, null));
        assertThrows(IllegalArgumentException.class, () -> new Input(StorageEvidence.NOT_ATTEMPTED, Delivery.NOT_ATTEMPTED, Cleanup.UNKNOWN));
        assertThrows(IllegalArgumentException.class, () -> new Input(StorageEvidence.INSERT_CONFIRMED, Delivery.COMPLETE, Cleanup.NOT_APPLICABLE));
    }
}
