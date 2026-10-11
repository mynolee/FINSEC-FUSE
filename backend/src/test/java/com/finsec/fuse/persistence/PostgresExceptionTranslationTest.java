package com.finsec.fuse.persistence;

import com.finsec.fuse.workflow.TransactionRetries;
import java.sql.SQLException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.PessimisticLockingFailureException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.TransactionSystemException;
import static org.junit.jupiter.api.Assertions.*;

/** Service-free classification controls; real rollback/commit behavior is covered by integration tests. */
class PostgresExceptionTranslationTest {
    private final TransactionRetries retries=new TransactionRetries();

    private DataAccessException translated(String sqlState) {
        var jdbc=new JdbcTemplate();
        new Db(jdbc); // Use the same exception configuration as production.
        var failure=jdbc.getExceptionTranslator().translate("classification control","SELECT 1",
            new SQLException("Injected PostgreSQL classification control",sqlState));
        assertNotNull(failure);
        return failure;
    }

    @ParameterizedTest
    @ValueSource(strings={"55P03","40001","40P01"})
    void knownLockSerializationAndDeadlockFailuresKeepExactlyTwoRetries(String sqlState) {
        var failure=translated(sqlState);
        assertInstanceOf(PessimisticLockingFailureException.class,failure);
        if("55P03".equals(sqlState))assertInstanceOf(CannotAcquireLockException.class,failure);
        var attempts=new AtomicInteger();
        var thrown=assertThrows(PessimisticLockingFailureException.class,()->retries.run((Runnable)()->{
            attempts.incrementAndGet();throw failure;
        }));
        assertSame(failure,thrown);
        assertEquals(3,attempts.get());
    }

    @ParameterizedTest
    @ValueSource(strings={"08006","57014"})
    void connectionLossAndStatementCancellationRemainNonretryable(String sqlState) {
        var failure=translated(sqlState);
        if("08006".equals(sqlState))assertInstanceOf(DataAccessResourceFailureException.class,failure);
        else assertInstanceOf(QueryTimeoutException.class,failure);
        var attempts=new AtomicInteger();
        var thrown=assertThrows(DataAccessException.class,()->retries.run((Runnable)()->{
            attempts.incrementAndGet();throw failure;
        }));
        assertSame(failure,thrown);
        assertEquals(1,attempts.get());
    }

    @ParameterizedTest
    @ValueSource(strings={"08006","55P03"})
    void transactionSystemFailureNeverRetriesEvenWithNestedLockState(String sqlState) {
        var failure=new TransactionSystemException("Injected uncertain transaction outcome",translated(sqlState));
        var attempts=new AtomicInteger();
        var thrown=assertThrows(TransactionSystemException.class,()->retries.run((Runnable)()->{
            attempts.incrementAndGet();throw failure;
        }));
        assertSame(failure,thrown);
        assertEquals(1,attempts.get());
    }
}
