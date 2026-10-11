package com.finsec.fuse.workflow;

import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.payment.PaymentAgentService;
import com.finsec.fuse.persistence.Db;
import jakarta.annotation.PreDestroy;
import org.slf4j.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Durable queue ownership stays in PostgreSQL; virtual threads are merely current lease holders. */
@Component
@org.springframework.context.annotation.DependsOn("runtimeSafety")
public class JobWorker {
    private static final Logger log=LoggerFactory.getLogger(JobWorker.class);
    private final JobTransactions jobs;private final KycTransactions kyc;private final KycGateway gateway;
    private final LoanTransactions loan;private final PaymentAgentService payment;private final TransactionRetries retries;
    private final Db db;private final boolean enabled;private final Semaphore slots;
    private final com.finsec.fuse.config.FuseReadinessHealthIndicator readiness;
    private final ExecutorService executor=Executors.newVirtualThreadPerTaskExecutor();
    private final AtomicBoolean available=new AtomicBoolean(true);
    public JobWorker(JobTransactions jobs,KycTransactions kyc,KycGateway gateway,LoanTransactions loan,PaymentAgentService payment,
                     TransactionRetries retries,Db db,FusePolicy policy,com.finsec.fuse.config.FuseReadinessHealthIndicator readiness,@Value("${fuse.worker-enabled:true}") boolean enabled) {
        this.jobs=jobs;this.kyc=kyc;this.gateway=gateway;this.loan=loan;this.payment=payment;this.retries=retries;
        this.db=db;this.readiness=readiness;this.enabled=enabled;this.slots=new Semaphore(policy.maxKycConcurrency());
    }
    @Scheduled(fixedDelayString="#{@fusePolicy.workerPollMs()}")
    public void poll() {
        if(!enabled || !org.springframework.boot.health.contributor.Status.UP.equals(readiness.health().getStatus()) || !slots.tryAcquire())return;
        try {
            if(!available.get()) {db.required("SELECT 1 AS ready");available.set(true);}
            var lease=retries.run(jobs::claim);
            if(lease.isEmpty()){slots.release();return;}
            executor.submit(()->{try{execute(lease.get());}finally{slots.release();}});
        }catch(DataAccessException failure){slots.release();unavailable();}
        catch(RuntimeException failure){slots.release();log.error("Worker claim failed; durable jobs remain recoverable");}
    }
    /** Useful for deterministic test/demo runners. Never synthesizes grants, approvals, or payments. */
    public boolean runOne() {
        var lease=retries.run(jobs::claim);if(lease.isEmpty())return false;
        execute(lease.get());return true;
    }
    public void execute(JobTransactions.Lease lease) {
        try {
            switch(lease.phase()) {
                case "KYC" -> {
                    var prepared=retries.run(()->kyc.prepare(lease.jobId(),lease.token()));
                    if(prepared.isPresent()) {
                        var response=gateway.evaluate(prepared.get().input());
                        retries.run(()->kyc.apply(prepared.get(),response));
                    }
                }
                case "LOAN" -> retries.run(()->loan.execute(lease.jobId(),lease.token()));
                case "PAY" -> retries.run(()->payment.execute(lease.jobId(),lease.token()));
                default -> throw new IllegalStateException("Unrecognized durable job phase");
            }
        }catch(KycClient.KycFailure failure) {
            hold(lease,failure.reasonCode());
        }catch(org.springframework.dao.PessimisticLockingFailureException failure) {
            if(!"PAY".equals(lease.phase()))hold(lease,"DEPENDENCY_UNAVAILABLE");
            else log.warn("Payment lock retries exhausted for {}; dedicated reaper will reconcile",lease.jobId());
        }catch(DataAccessException failure) {
            // Unknown commit outcomes must remain recoverable by lease reaping, never guessed.
            unavailable();log.warn("Job database operation failed for {}; keeping durable lease for recovery",lease.jobId());
        }catch(RuntimeException failure) {
            log.error("Job execution failed for {}; durable recovery required",lease.jobId());
            if(!"PAY".equals(lease.phase()))hold(lease,"DEPENDENCY_UNAVAILABLE");
            // PAY may have committed or reserved. Its dedicated reaper reconciles the ledger.
        }
    }
    private void hold(JobTransactions.Lease lease,String reason) {
        try {retries.run(()->jobs.fail(lease.jobId(),lease.token(),reason));}
        catch(DataAccessException failure){unavailable();}
    }
    private void unavailable(){if(available.getAndSet(false))log.warn("Database unavailable; worker claims paused until connectivity is restored");}
    @PreDestroy public void stop(){executor.shutdownNow();}
}
