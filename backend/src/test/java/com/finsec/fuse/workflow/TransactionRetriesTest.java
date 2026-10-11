package com.finsec.fuse.workflow;
import org.junit.jupiter.api.Test;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.DataAccessResourceFailureException;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;
class TransactionRetriesTest {
    @Test void retriesOnlyKnownRollbackAndNeverMoreThanTwice() {
        var attempts=new AtomicInteger();
        assertThrows(CannotAcquireLockException.class,()->new TransactionRetries().run((Runnable)()->{attempts.incrementAndGet();throw new CannotAcquireLockException("synthetic lock failure");}));
        assertEquals(3,attempts.get());
        attempts.set(0);
        assertThrows(DataAccessResourceFailureException.class,()->new TransactionRetries().run((Runnable)()->{attempts.incrementAndGet();throw new DataAccessResourceFailureException("synthetic unknown commit outcome");}));
        assertEquals(1,attempts.get());
    }
}
