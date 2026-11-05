package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import com.finsec.fuse.reimplementation.simulation.VirtualProductAssembly;
import java.util.Objects;

/** Trusted object composition only. No no-arg SPI fallback or credential acquisition. */
public final class DataConfiguredVirtualApplicationFactory implements PreparedVirtualApplicationFactory {
    private final PreparedVirtualConfiguration configuration;
    private final PreparedSecurityBindings security;
    private final PreparedSyntheticProviders providers;
    private final PreparedResourceLease lease;
    public DataConfiguredVirtualApplicationFactory(PreparedVirtualConfiguration configuration,
            PreparedSecurityBindings security,PreparedSyntheticProviders providers,PreparedResourceLease lease){
        this.configuration=Objects.requireNonNull(configuration);this.security=Objects.requireNonNull(security);
        this.providers=Objects.requireNonNull(providers);this.lease=Objects.requireNonNull(lease);
    }
    public static final class PreparationFailure extends RuntimeException {
        private final PreparedResourceLease.Cleanup cleanup;
        private PreparationFailure(PreparedResourceLease.Cleanup cleanup){super("PREPARED_CONFIGURATION_UNAVAILABLE",null,false,false);this.cleanup=cleanup;}
        public PreparedResourceLease.Cleanup cleanup(){return cleanup;}
    }
    @Override public synchronized Prepared prepare(){
        lease.claim();
        try{
            var inputs=new VirtualProductAssembly.Inputs(new VirtualTransactionalStore(),configuration.catalog(),
                    configuration.riskTerms(),security.authority(),security.remediationVerifier(),configuration.fixtureSets(),
                    providers.pairs(),configuration.clock(),configuration.actionIds(),security.startResumeActors(),
                    security.otherActors(),configuration.listener().application().httpLimits());
            var delivery=new VirtualProductAssembly.DeliveryInputs(lease.executor(),configuration.deliveryActor(),
                    providers.kyc(),configuration.actionIds(),configuration.maximumInFlight());
            var result=new Prepared(configuration.listener(),inputs,delivery,security.readiness(),
                    security.dependenciesAvailable(),lease.ownership());
            lease.transfer();return result;
        }catch(RuntimeException failed){lease.close();throw new PreparationFailure(lease.cleanup());}
    }
    @Override public String toString(){return "DataConfiguredVirtualApplicationFactory[REDACTED]";}
}
