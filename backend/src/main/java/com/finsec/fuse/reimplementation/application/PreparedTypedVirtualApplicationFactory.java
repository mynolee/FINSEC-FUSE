package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import com.finsec.fuse.reimplementation.simulation.VirtualProductAssembly;

/** Explicit typed-and-delivery assembly; no no-arg SPI population, network or authority defaults. */
public final class PreparedTypedVirtualApplicationFactory implements PreparedVirtualApplicationFactory {
    private final PreparedVirtualConfiguration configuration;
    private final PreparedSecurityBindings security;
    private final PreparedSyntheticProviders providers;
    private final PreparedResourceLease lease;
    private final PreparedTypedInputs typed;
    public PreparedTypedVirtualApplicationFactory(PreparedVirtualConfiguration configuration,
            PreparedSecurityBindings security,PreparedSyntheticProviders providers,PreparedResourceLease lease,
            PreparedTypedInputs typed){
        if(configuration==null||security==null||providers==null||lease==null||typed==null)throw missing();
        typed.security().requireBindings(security.authority(),security.startResumeActors(),security.otherActors(),configuration.clock());
        if(typed.continuation().catalog()!=configuration.catalog())throw missing();
        this.configuration=configuration;this.security=security;this.providers=providers;this.lease=lease;this.typed=typed;
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
                    security.otherActors(),configuration.listener().application().httpLimits(),typed.security());
            var delivery=new VirtualProductAssembly.DeliveryInputs(lease.executor(),configuration.deliveryActor(),
                    providers.kyc(),configuration.actionIds(),configuration.maximumInFlight());
            var prepared=new Prepared(configuration.listener(),inputs,delivery,security.readiness(),
                    security.dependenciesAvailable(),lease.ownership(),typed);
            lease.transfer();return prepared;
        }catch(RuntimeException failed){lease.close();throw new PreparationFailure(lease.cleanup());}
    }
    private static IllegalStateException missing(){return new IllegalStateException("CONFIGURATION_REQUIRED",null);}
    @Override public String toString(){return "PreparedTypedVirtualApplicationFactory[REDACTED]";}
}
