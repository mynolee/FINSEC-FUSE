package com.finsec.fuse.reimplementation.grant;

import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentPlanBinding.*;

/** Explicit review/reservation phases sharing the existing owned global journal. */
public interface OwnedMockPaymentPlanPort extends OwnedRootProvisionPort {
    interface OwnedPlanTx {
        PlanReceipt lookupReview(ReviewCommand command);
        PlanReceipt lookupReservation(ReserveCommand command);
        void admitReview(ReviewCommand command);
        void admitReservation(ReserveCommand command);
        ReviewBindings readReviewBindings(ReviewCommand command);
        ReservationBindings readReservationBindings(ReserveCommand command);
        PlanReceipt recordReview(ReviewCommand command, PreparedReview prepared);
        PlanReceipt recordReservation(ReserveCommand command, PreparedReservation prepared);
    }
    interface PlanWork { PlanOutcome apply(OwnedPlanTx tx); }
    PlanOutcome review(ReviewCommand command, PlanWork work);
    PlanOutcome reserve(ReserveCommand command, PlanWork work);
}
