package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.http.PreparedTypedActionCatalog;
import com.finsec.fuse.reimplementation.simulation.VirtualProductAssembly;

/** Explicit prepared typed HTTP graph. Contains no credential acquisition or default current facts. */
public record PreparedTypedInputs(VirtualProductAssembly.TypedInputs typed,
        VirtualProductAssembly.ContinuationInputs continuation,PreparedTypedActionCatalog actions,
        PreparedLocalVirtualSecurity security,
        com.finsec.fuse.reimplementation.http.TypedWorkflowMutationController.CurrentCoordinates currentCoordinates) {
    public PreparedTypedInputs {
        if(typed==null||continuation==null||actions==null||security==null||currentCoordinates==null
                ||typed.facts()!=continuation.facts())throw missing();
    }
    public void requireBindings(VirtualProductAssembly.Inputs inputs){
        if(inputs==null||inputs.localAuthentication()!=security||continuation.catalog()!=inputs.catalog())throw missing();
        security.requireBindings(inputs.authority(),inputs.startResumeActors(),inputs.otherActors(),inputs.clock());
    }
    private static IllegalStateException missing(){return new IllegalStateException("CONFIGURATION_REQUIRED",null);}
    @Override public String toString(){return "PreparedTypedInputs[REDACTED]";}
}
