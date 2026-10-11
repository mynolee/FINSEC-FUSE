package com.finsec.fuse.workflow;

import com.finsec.fuse.payment.PaymentAgentService;
import org.slf4j.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import static com.finsec.fuse.workflow.WorkflowValues.*;

@Component
@org.springframework.context.annotation.DependsOn("runtimeSafety")
public class LeaseReaper {
    private static final Logger log=LoggerFactory.getLogger(LeaseReaper.class);
    private final JobTransactions jobs;private final PaymentAgentService payment;private final TransactionRetries retries;private final boolean enabled;
    public LeaseReaper(JobTransactions jobs,PaymentAgentService payment,TransactionRetries retries,@Value("${fuse.worker-enabled:true}") boolean enabled) {
        this.jobs=jobs;this.payment=payment;this.retries=retries;this.enabled=enabled;
    }
    @Scheduled(fixedDelayString="#{@fusePolicy.reaperPollMs()}")
    public void poll(){if(enabled)reap();}
    public void reap() {
        try {
            for(var job:jobs.expired()) {
                if("PAY".equals(str(job,"phase")))retries.run(()->payment.reap(id(job,"id")));
                else retries.run(()->jobs.reapNonPayment(id(job,"id")));
            }
        }catch(RuntimeException failure){log.warn("Lease reconciliation could not complete; durable leases remain pending");}
    }
}
