package com.finsec.fuse.reimplementation.simulation;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.simulation.SimulationFixture.*;
import static com.finsec.fuse.reimplementation.simulation.SimulationSpec.object;
import static com.finsec.fuse.reimplementation.simulation.VirtualDeliveryCoordinator.Submission.*;
import static org.junit.jupiter.api.Assertions.*;

/** Deterministic synthetic delivery boundaries with explicitly drained work. */
final class VirtualDeliveryCoordinatorTest {
    private static final class Held implements Executor {
        final List<Runnable> tasks = new ArrayList<>();
        boolean reject;
        public void execute(Runnable task) {
            tasks.add(task);
            if (reject) throw new RejectedExecutionException("synthetic queue rejection");
        }
        void drain() { var copy = List.copyOf(tasks); tasks.clear(); copy.forEach(Runnable::run); }
    }
    private Map<String,Object> response(Map<String,Object> input) {
        return object("requestId",input.get("requestId"),"workflowId",input.get("workflowId"),
                "generation",input.get("generation"),"runId",input.get("runId"),
                "inputSnapshotHash",input.get("inputSnapshotHash"),
                "proposal",object("status","VERIFIED","evidenceIds",List.of(ID_FACT.toString(),FACE_FACT.toString()),
                        "explanation","synthetic delivery"),
                "modelMetadata",object("model","synthetic","promptVersion","synthetic-v1"));
    }
    private VirtualDeliveryCoordinator coordinator(SimulationFixture f, Executor executor, int cap,
            Supplier<UUID> ids, java.util.function.Function<Map<String,Object>,Map<String,Object>> evaluation) {
        var provider = new VirtualKycJobAdapter.ProviderPort() {
            public String mode() { return "VIRTUAL_NON_DURABLE"; }
            public Map<String,Object> evaluate(VirtualKycJobAdapter.Delivery delivery, Map<String,Object> input) {
                return evaluation.apply(input);
            }
        };
        var adapter = new VirtualKycJobAdapter(f.store,new VirtualAgentBridge(f.workflows),provider);
        var experiments = new VirtualExperimentService(f.store,f.access,List.of(
                new VirtualExperimentService.FixtureSet("synthetic-delivery",List.of(
                    new VirtualExperimentService.Case("synthetic-normal",SimulationSpec.KycStatus.VERIFIED,List.of(ID_FACT,FACE_FACT))))),
                new VirtualExperimentService.PairEvaluator() {
                    public String mode() { return "VIRTUAL_NON_DURABLE"; }
                    public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment,
                            String id,int repeat,Map<String,Object> proposal) {
                        throw new AssertionError("Experiment work is outside this workflow fixture");
                    }
                },f::id);
        return new VirtualDeliveryCoordinator(executor,ACTOR,f.workflows,adapter,experiments,ids,cap);
    }
    @Test void heldPositiveWorkIsDeduplicatedAndOnlyDrainCallsProvider() {
        var f=new SimulationFixture(); var queue=new Held(); var calls=new AtomicInteger(); UUID id=f.start();
        var c=coordinator(f,queue,1,f::id,input->{calls.incrementAndGet();return response(input);});
        assertEquals(ACCEPTED,c.enqueueKyc(id,1)); assertEquals(SKIPPED,c.enqueueKyc(id,1));
        assertEquals(1,c.status().queued()); assertEquals(0,calls.get()); assertEquals(1,queue.tasks.size());
        queue.drain(); assertEquals(1,calls.get()); assertEquals("WAIT_APPROVAL",f.workflows.get(ACTOR,id).get("state"));
        assertEquals(new VirtualDeliveryCoordinator.DispatchStatus(0,0,0,0),c.status());
        assertEquals(SKIPPED,c.enqueueKyc(id,1));
    }
    @Test void explicitCapacityRejectsDifferentActualJobWithoutChangingCommittedStart() {
        var f=new SimulationFixture(); var queue=new Held(); UUID first=f.start(),second=f.workflows.start(new com.finsec.fuse.reimplementation.WorkflowStartBoundary.Command(
                ACTOR,f.id(),f.second.request())).workflowId();
        var c=coordinator(f,queue,1,f::id,this::response); var before=f.store.snapshot();
        assertEquals(ACCEPTED,c.enqueueKyc(first,1)); assertEquals(UNAVAILABLE,c.enqueueKyc(second,1));
        assertEquals(before,f.store.snapshot()); assertEquals("KYC_PENDING",f.workflows.get(ACTOR,second).get("state"));
        assertEquals(1,c.status().queued()); assertEquals(1L,c.status().rejected());
        queue.drain(); assertEquals(ACCEPTED,c.enqueueKyc(second,1)); queue.drain();
        assertEquals("WAIT_APPROVAL",f.workflows.get(ACTOR,second).get("state"));
    }
    @Test void synchronousInlineExecutorRefusesBeforeProviderAndDomainWrites() {
        var f=new SimulationFixture(); UUID id=f.start(); var calls=new AtomicInteger();
        var c=coordinator(f,Runnable::run,1,f::id,input->{calls.incrementAndGet();return response(input);});
        var before=f.store.snapshot(); assertEquals(UNAVAILABLE,c.enqueueKyc(id,1));
        assertEquals(0,calls.get()); assertEquals(before,f.store.snapshot());
        assertEquals(new VirtualDeliveryCoordinator.DispatchStatus(0,0,0,1),c.status());
    }
    @Test void rejectedRetainedRunnableCannotExecuteAndExplicitKnownRecoveryCanProceed() {
        var f=new SimulationFixture(); UUID id=f.start(); var queue=new Held();queue.reject=true;
        var calls=new AtomicInteger();var c=coordinator(f,queue,1,f::id,input->{calls.incrementAndGet();return response(input);});
        var before=f.store.snapshot();assertEquals(UNAVAILABLE,c.enqueueKyc(id,1));
        assertEquals(before,f.store.snapshot()); queue.drain();assertEquals(0,calls.get());
        queue.reject=false;assertEquals(ACCEPTED,c.enqueueKyc(id,1));queue.drain();assertEquals(1,calls.get());
    }
    @Test void unknownActionAllocationRetainsCapacityWithoutAutomaticRetry() {
        var f=new SimulationFixture(); UUID id=f.start(); var queue=new Held();var allocations=new AtomicInteger();
        var calls=new AtomicInteger();var c=coordinator(f,queue,1,()->{
            allocations.incrementAndGet();throw new IllegalStateException("synthetic unavailable");
        },input->{calls.incrementAndGet();return response(input);});
        assertEquals(ACCEPTED,c.enqueueKyc(id,1));queue.drain();
        assertEquals(1,c.status().unknown());assertEquals(SKIPPED,c.enqueueKyc(id,1));
        queue.drain();assertEquals(1,allocations.get());assertEquals(0,calls.get());
        assertEquals("KYC_PENDING",f.workflows.get(ACTOR,id).get("state"));
    }
    @Test void wrongGenerationAndNewHoldBeforeDrainDoNotWriteOrCallProvider() {
        var f=new SimulationFixture(); UUID id=f.start();var queue=new Held();var calls=new AtomicInteger();
        var c=coordinator(f,queue,1,f::id,input->{calls.incrementAndGet();return response(input);});
        assertEquals(SKIPPED,c.enqueueKyc(id,2));assertTrue(queue.tasks.isEmpty());
        assertEquals(ACCEPTED,c.enqueueKyc(id,1));f.quarantine(id);var held=f.store.snapshot();
        queue.drain();assertEquals(0,calls.get());assertEquals(held,f.store.snapshot());
        assertEquals(0,c.status().queued());assertEquals(0,c.status().unknown());
    }
    @Test void runningDiagnosticDoesNotPermitSameKeyReentry() {
        var f=new SimulationFixture(); UUID id=f.start();var queue=new Held();
        var ref=new AtomicReference<VirtualDeliveryCoordinator>();var calls=new AtomicInteger();
        var c=coordinator(f,queue,1,f::id,input->{
            calls.incrementAndGet();assertEquals(1,ref.get().status().running());
            assertEquals(SKIPPED,ref.get().enqueueKyc(id,1));return response(input);
        });ref.set(c);
        assertEquals(ACCEPTED,c.enqueueKyc(id,1));queue.drain();
        assertEquals(1,calls.get());assertEquals(0,c.status().running());assertEquals(0,c.status().unknown());
    }
    @Test void rejectedOldInlineFlightCannotRemoveNewReentrantSameKeyFlight() {
        var f=new SimulationFixture(); UUID id=f.start();var ref=new AtomicReference<VirtualDeliveryCoordinator>();
        var queued=new ArrayList<Runnable>();var submissions=new AtomicInteger();var calls=new AtomicInteger();
        Executor executor=task->{
            if (submissions.incrementAndGet()==1) {
                task.run(); // Refuses inline and removes only the original Flight.
                assertEquals(ACCEPTED,ref.get().enqueueKyc(id,1));
                assertEquals(1,ref.get().status().queued());
                throw new RejectedExecutionException("synthetic old submission failure");
            }
            queued.add(task); // New Flight's task is not executed on the enqueue stack.
        };
        var c=coordinator(f,executor,1,f::id,input->{calls.incrementAndGet();return response(input);});ref.set(c);
        assertEquals(UNAVAILABLE,c.enqueueKyc(id,1));
        assertEquals(2,submissions.get());assertEquals(1,queued.size());
        assertEquals(1,c.status().queued());assertEquals(0,c.status().unknown());assertEquals(0,calls.get());
        assertEquals(SKIPPED,c.enqueueKyc(id,1));
        queued.get(0).run();
        assertEquals(1,calls.get());assertEquals("WAIT_APPROVAL",f.workflows.get(ACTOR,id).get("state"));
        assertEquals(0,c.status().queued());assertEquals(0,c.status().running());assertEquals(0,c.status().unknown());
        queued.get(0).run();assertEquals(1,calls.get());
    }
    @Test void invalidExplicitCapacityDoesNotAcquireAnExecutorOrProvider() {
        var f=new SimulationFixture();var queue=new Held();
        assertThrows(IllegalArgumentException.class,()->coordinator(f,queue,0,f::id,this::response));
        assertTrue(queue.tasks.isEmpty());
    }
}
