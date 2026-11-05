package com.finsec.fuse.reimplementation.application;

import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/** One-shot explicit resource handoff. Does not allocate, start or submit work. */
public final class PreparedResourceLease implements AutoCloseable {
    public enum State { AVAILABLE, CLAIMED, TRANSFERRED, CLOSED }
    public enum Cleanup { NOT_ATTEMPTED, OWNED_TERMINATION_ACKNOWLEDGED, UNCONFIRMED, BORROWED_NOT_CLOSED, TRANSFERRED_TO_PREPARED }
    private final Executor executor;
    private final ConfiguredVirtualApplicationHost.DeliveryOwnership ownership;
    private State state=State.AVAILABLE;
    private Cleanup cleanup=Cleanup.NOT_ATTEMPTED;
    private PreparedResourceLease(Executor executor,ConfiguredVirtualApplicationHost.DeliveryOwnership ownership){
        this.executor=Objects.requireNonNull(executor);this.ownership=Objects.requireNonNull(ownership);
    }
    public static PreparedResourceLease owned(ExecutorService executor,long shutdownWaitMillis){
        return new PreparedResourceLease(executor,new ConfiguredVirtualApplicationHost.OwnedExecutor(executor,shutdownWaitMillis));
    }
    public static PreparedResourceLease borrowed(Executor executor){
        return new PreparedResourceLease(executor,new ConfiguredVirtualApplicationHost.BorrowedDelivery());
    }
    synchronized void claim(){if(state!=State.AVAILABLE)throw invalid();state=State.CLAIMED;}
    synchronized Executor executor(){if(state!=State.CLAIMED)throw invalid();return executor;}
    synchronized ConfiguredVirtualApplicationHost.DeliveryOwnership ownership(){if(state!=State.CLAIMED)throw invalid();return ownership;}
    synchronized void transfer(){if(state!=State.CLAIMED)throw invalid();state=State.TRANSFERRED;cleanup=Cleanup.TRANSFERRED_TO_PREPARED;}
    public synchronized State state(){return state;}
    public synchronized Cleanup cleanup(){return cleanup;}
    @Override public synchronized void close(){
        if(state==State.CLOSED||state==State.TRANSFERRED)return;
        state=State.CLOSED;
        if(ownership instanceof ConfiguredVirtualApplicationHost.OwnedExecutor owned){
            cleanup=Cleanup.UNCONFIRMED;
            try{owned.executor().shutdown();if(owned.executor().awaitTermination(owned.shutdownWaitMillis(),TimeUnit.MILLISECONDS))cleanup=Cleanup.OWNED_TERMINATION_ACKNOWLEDGED;}
            catch(InterruptedException interrupted){Thread.currentThread().interrupt();}
            catch(RuntimeException unavailable){cleanup=Cleanup.UNCONFIRMED;}
        }else cleanup=Cleanup.BORROWED_NOT_CLOSED;
    }
    private static IllegalStateException invalid(){return new IllegalStateException("PREPARED_RESOURCE_LEASE_UNAVAILABLE");}
    @Override public String toString(){return "PreparedResourceLease[REDACTED]";}
}
