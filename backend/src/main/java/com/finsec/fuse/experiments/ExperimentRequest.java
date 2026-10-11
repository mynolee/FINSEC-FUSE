package com.finsec.fuse.experiments;

import jakarta.validation.constraints.*;
import com.finsec.fuse.common.ApiException;
import java.util.List;

public record ExperimentRequest(@NotBlank String fixtureSetId,@NotNull @Size(max=60) List<String> caseIds,
    @NotNull Mode mode,@NotNull ModelMode modelMode,@Min(1) @Max(10) int repeatCount) {
    public void validate(boolean liveEnabled) {
        if(mode!=Mode.PAIRED || modelMode==null || repeatCount<1 || repeatCount>10 ||
                (modelMode==ModelMode.LIVE && repeatCount!=3) || (modelMode==ModelMode.REPLAY && repeatCount!=1))
            throw new ApiException(400,"INVALID_REQUEST","REPLAY requires one repeat and LIVE requires exactly three repeats.");
        if(modelMode==ModelMode.LIVE && !liveEnabled)
            throw new ApiException(400,"LIVE_NOT_AVAILABLE","LIVE paired capture is disabled. No external model was called.");
    }
    public enum Mode { PAIRED }
    public enum ModelMode { REPLAY, LIVE }
}
