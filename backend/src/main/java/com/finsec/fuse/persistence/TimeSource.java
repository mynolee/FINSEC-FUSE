package com.finsec.fuse.persistence;

import java.time.Instant;

/** Authority time: acquire transaction locks before calling; bind this instant in every deadline predicate. */
public interface TimeSource { Instant now(); }
