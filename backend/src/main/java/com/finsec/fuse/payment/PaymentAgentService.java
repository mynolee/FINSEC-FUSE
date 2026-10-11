package com.finsec.fuse.payment;

import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;

/** Reservation and final execution deliberately cross two independent transaction proxies. */
@Service
public class PaymentAgentService {
    private final PaymentTxService transactions;
    private final ObjectProvider<PaymentTestHooks> hooks;
    public PaymentAgentService(PaymentTxService transactions, ObjectProvider<PaymentTestHooks> hooks) {
        this.transactions = transactions;
        this.hooks = hooks;
    }
    public Map<String, Object> execute(UUID jobId, UUID leaseToken) {
        Map<String, Object> reserved = transactions.reserve(jobId, leaseToken);
        if (!"PAYMENT_RESERVED".equals(reserved.get("state"))) return reserved;
        hooks.ifAvailable(PaymentTestHooks::afterReservation);
        return transactions.commit(jobId, leaseToken);
    }
    public void reap(UUID jobId) { transactions.reap(jobId); }
}
