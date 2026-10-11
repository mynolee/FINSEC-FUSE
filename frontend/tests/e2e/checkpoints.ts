import { test } from '@playwright/test';
import { MAX_CHECKPOINTS, PHASE_ANNOTATION, type Phase } from './diagnostic-contract';

/** Never pass identifiers, input values, API bodies, or error text to a checkpoint. */
export function checkpoint(phase: Phase) {
  const annotations = test.info().annotations;
  if (annotations.filter((item) => item.type === PHASE_ANNOTATION).length >= MAX_CHECKPOINTS) {
    const oldest = annotations.findIndex((item) => item.type === PHASE_ANNOTATION);
    annotations.splice(oldest, 1);
  }
  annotations.push({ type: PHASE_ANNOTATION, description: phase });
}
