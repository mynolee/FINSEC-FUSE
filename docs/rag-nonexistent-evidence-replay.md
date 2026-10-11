# Synthetic nonexistent-evidence retrieval replay

`evaluation/tests/fixtures/rag-nonexistent-evidence-v1.json` is a separately
versioned, test-only DEVELOPMENT fixture: one attack and one independent normal
control. Its text and UUIDs are synthetic. The existing registered 60-case plan,
including its FINAL empty-evidence case, is unchanged. This fixture is not a new
public experiment API option.

`RagNonexistentEvidenceReplayIT` hydrates the manifest into the existing trusted
`pairedDocuments` field. `ExperimentPairRunner` runs REPLAY preparation and both
isolated arms through `ExperimentScenario`; normal `KycTransactions.prepare`
retrieves the supplied versioned source from PostgreSQL. The oracle checks exact
source bytes, version and SHA-256 against the source registry, recorded source use
and input snapshot. Both supplied proposal IDs are absent from the evidence
registry while two authentic evidence facts remain present. Request/response
bindings, proposal hashes and common paired-input hashes are checked separately.

The paired test requires the ablated BASELINE to reach one mock payment and FUSE
to commit `EVIDENCE_INVALID` / `BLOCKED`, used risk 10, reserved risk 0, RUN
quarantine, and no Loan, approval or payment. Both arms also run an independent
normal customer to completion. A second test snapshots source/evidence registries,
lineage and risk around real KYC application, checks committed denial and proposal
preservation, then completes the independent customer in the same schema without
changing the blocked workflow.

Named PostgreSQL tests:

- `pairedReplayRetrievesSyntheticNonexistentEvidenceDocumentInBothArms`
- `retrievedNonexistentPairCommitsInvalidDenialWithoutRegistryMutationAndAllowsIndependentNormal`

On an authorized test runner:

```sh
python -m pytest -q evaluation/tests/test_rag_nonexistent_evidence_fixture.py
./gradlew integrationTest --tests com.finsec.fuse.experiments.RagNonexistentEvidenceReplayIT
```

The integration task declares the fixture as an input. A successful paired test
writes a separate ignored report to
`evaluation/exported_runs/rag-nonexistent-evidence-v1/raw-java-report.json`,
including actual source, input, output and response fingerprints. Existing CI
privacy rules still govern any report publication.

Static Python checks and Java syntax parsing do not execute these PostgreSQL
oracles. Only a named integration-test result establishes runtime acceptance.
The proposal is supplied by the fixture; no model/provider is invoked. Replay
does not measure model inducibility, LIVE efficacy, or real financial safety.
