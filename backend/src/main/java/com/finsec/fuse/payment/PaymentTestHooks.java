package com.finsec.fuse.payment;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/** Deterministic transaction race barriers. This bean never exists in demo/production profiles. */
@Component
@Profile("test")
public class PaymentTestHooks {
    private volatile Runnable afterReservation = () -> {};
    private volatile Runnable afterCommitGate = () -> {};
    public void afterReservation() { afterReservation.run(); }
    public void afterCommitGate() { afterCommitGate.run(); }
    public void onAfterReservation(Runnable hook) { afterReservation = hook; }
    public void onAfterCommitGate(Runnable hook) { afterCommitGate = hook; }
    public void reset() { afterReservation = () -> {}; afterCommitGate = () -> {}; }
}
