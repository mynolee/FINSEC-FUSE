package com.finsec.fuse.workflow;

import org.springframework.dao.PessimisticLockingFailureException;
import org.springframework.stereotype.Component;
import java.util.function.Supplier;
import java.util.concurrent.locks.LockSupport;

/** Only known rolled-back lock/deadlock failures retry; action and lease stay unchanged. */
@Component
public class TransactionRetries {
    public <T> T run(Supplier<T> operation) {
        for(int attempt=0;;attempt++) {
            try{return operation.get();}
            catch(PessimisticLockingFailureException failure) {
                if(attempt>=2)throw failure;
                LockSupport.parkNanos((attempt+1)*25_000_000L);
                if(Thread.currentThread().isInterrupted())throw failure;
            }
        }
    }
    public void run(Runnable operation){run(()->{operation.run();return null;});}
}
