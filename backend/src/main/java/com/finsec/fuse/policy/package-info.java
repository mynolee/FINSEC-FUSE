/**
 * Central Java policy boundary for the mock-only financial workflow.
 *
 * <p>Evidence is read exclusively from the independent registry and bound to the IDs actually
 * supplied to a run. Documents, model explanations and model-provided principals do not authorize
 * anything. Hashes detect mutation; they do not establish truth. KYC is a proposal until validation.
 *
 * <p>FUSE-GRANT-v1 is an HMAC-authenticated private transport, not JWS, A2A, or a public-key signature.
 * Validation uses received bytes before strict JSON parsing and compares both bytes and registered
 * columns. Current grants expire at the database-time boundary; consumed ancestor grants remain
 * historical provenance and are not required to be unexpired when a reviewer later approves.
 *
 * <p>Services are intentionally not transaction boundaries: the orchestrator owns the common
 * execution gate, workflow locks, database-time sample, denial persistence and audit transaction.
 * An external invalid envelope must never quarantine someone else's workflow. PolicyException is
 * an internal refusal and must be converted to a committed decision if denial records were written.
 * The read-only checks do not claim that a payment occurred. Only the atomic mock ledger can do so.
 */
package com.finsec.fuse.policy;
