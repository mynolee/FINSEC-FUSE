package com.finsec.fuse.experiments;

import com.finsec.fuse.workflow.KycContract;

/** One bounded model call, used only by explicitly enabled LIVE experiments. */
@FunctionalInterface
public interface ExperimentCaptureGateway {
    ExperimentModelCapture capture(KycContract.Input input);
}
