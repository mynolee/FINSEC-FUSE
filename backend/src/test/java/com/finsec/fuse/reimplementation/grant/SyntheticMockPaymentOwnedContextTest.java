package com.finsec.fuse.reimplementation.grant;

import com.finsec.fuse.reimplementation.persistence.TransactionalStore;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentTransactionBinding.*;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic facade lifetime checks only; no real provider, database or thread was used to author this source. */
class SyntheticMockPaymentOwnedContextTest {
    static final class CountingStore implements TransactionalStore {
        final VirtualTransactionalStore delegate = new VirtualTransactionalStore();
        final AtomicInteger accesses = new AtomicInteger();
        public String mode() { return delegate.mode(); }
        public Map<String, Map<String, Map<String, Object>>> snapshot() { return delegate.snapshot(); }
        public <R> R transaction(Function<Tx, R> work) {
            return delegate.transaction(tx -> work.apply(new Tx() {
                public Map<String, Object> get(String table, String id) {
                    accesses.incrementAndGet(); return tx.get(table, id);
                }
                public Map<String, Map<String, Object>> rows(String table) {
                    accesses.incrementAndGet(); return tx.rows(table);
                }
                public void put(String table, String id, Map<String, Object> row) {
                    accesses.incrementAndGet(); tx.put(table, id, row);
                }
            }));
        }
    }
    static final class Fixture {
        final CountingStore store = new CountingStore();
        final VirtualGrantTransactionJournal journal = VirtualGrantTransactionJournal.detachedReference(
                store, () -> SyntheticMockPaymentTransactionBindingTest.id(90), 65536);
        final PaymentCommand command = SyntheticMockPaymentTransactionBindingTest.command(
                SyntheticMockPaymentTransactionBindingTest.input());
        final ResolvedPayment payment = SyntheticMockPaymentTransactionBindingTest.resolved(command);
        OwnedTx retained() {
            AtomicReference<OwnedTx> value = new AtomicReference<>();
            StageOutcome result = journal.transact(command.stage(), tx -> {
                value.set(tx); return absent();
            });
            assertEquals(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH, result.status());
            store.accesses.set(0); return value.get();
        }
    }
    static StageOutcome absent() {
        return StageOutcome.of(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH, null, EffectKnowledge.UNKNOWN);
    }
    static void unavailable(Throwable failure) {
        assertInstanceOf(IllegalStateException.class, failure);
        assertEquals("OWNED_GRANT_TRANSACTION_UNAVAILABLE", failure.getMessage());
    }
    /** Fixture deadlines are test-local liveness limits, not product timeouts or hard isolation. */
    static Throwable onForeignThread(Runnable work) {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread worker = new Thread(() -> {
            try { work.run(); } catch (Throwable caught) { failure.set(caught); }
        });
        worker.setDaemon(true);
        try {
            worker.start(); worker.join(1000);
            if (worker.isAlive()) { worker.interrupt(); worker.join(1000); }
            assertFalse(worker.isAlive(), "synthetic worker did not finish within fixture bounds");
        } catch (InterruptedException primary) {
            worker.interrupt(); Thread.currentThread().interrupt();
            throw new AssertionError("synthetic primary thread interrupted", primary);
        } finally {
            if (worker.isAlive()) worker.interrupt();
        }
        return failure.get();
    }

    @Test void paymentDomainAfterCallbackFailsBeforeAnyStoreRead() {
        Fixture f = new Fixture(); OwnedTx retired = f.retained();
        unavailable(assertThrows(IllegalStateException.class,
                () -> retired.paymentDomain(f.command.expectedReceipt().reservationId())));
        assertEquals(0, f.store.accesses.get());
    }

    @Test void commitMockPaymentAfterCallbackFailsBeforeAnyStoreAccess() {
        Fixture f = new Fixture(); OwnedTx retired = f.retained();
        unavailable(assertThrows(IllegalStateException.class,
                () -> retired.commitMockPayment(f.command.stage(), f.payment)));
        assertEquals(0, f.store.accesses.get());
    }

    @Test void paymentDomainOnForeignThreadFailsWhileOwningCallbackRemainsOpen() {
        Fixture f = new Fixture();
        StageOutcome result = f.journal.transact(f.command.stage(), tx -> {
            f.store.accesses.set(0);
            unavailable(onForeignThread(() -> tx.paymentDomain(f.command.expectedReceipt().reservationId())));
            assertEquals(0, f.store.accesses.get()); return absent();
        });
        assertEquals(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH, result.status());
        assertFalse(result.actualAuthority()); assertFalse(result.durable());
    }

    @Test void commitMockPaymentOnForeignThreadFailsWhileOwningCallbackRemainsOpen() {
        Fixture f = new Fixture();
        StageOutcome result = f.journal.transact(f.command.stage(), tx -> {
            f.store.accesses.set(0);
            unavailable(onForeignThread(() -> tx.commitMockPayment(f.command.stage(), f.payment)));
            assertEquals(0, f.store.accesses.get()); return absent();
        });
        assertEquals(Status.NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH, result.status());
        assertFalse(result.actualAuthority()); assertFalse(result.durable());
    }
}
