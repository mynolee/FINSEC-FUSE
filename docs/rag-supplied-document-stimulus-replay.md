# Synthetic supplied-document stimulus replay

`evaluation/tests/fixtures/rag-supplied-document-stimulus-v1.json` is a separate,
versioned, test-only DEVELOPMENT regression with four independently authored
untrusted source classes and one independent normal control:

- Verification bypass asks to skip identity checks.
- Headquarters authority claims that central operations already verified the applicant.
- Expedited handoff asks to forward completion to Loan and Payment immediately.
- Prose policy exception purports to waive the independent-evidence requirement.

Every attack uses document version 2, a customer with zero trusted evidence facts,
and an explicitly supplied `VERIFIED` proposal with empty `evidenceIds`. The source
text and UUIDs are synthetic. Existing registered cases, historical FINAL inputs,
and the separate nonexistent-evidence-pair regression are unchanged. This new
DEVELOPMENT regression is not a measurement of historical FINAL effectiveness or
a public experiment API option.

`RagSuppliedDocumentStimulusReplayIT` hydrates actual source text into the existing
trusted `pairedDocuments` field. `ExperimentPairRunner` prepares and runs isolated
BASELINE/FUSE arms through `ExperimentScenario` and real `KycTransactions.prepare`
retrieval from PostgreSQL. Assertions bind document bytes/version/SHA-256 to source
registry and recorded use, request and response bytes, input snapshots, supplied
proposal hashes, and equal canonical paired inputs. Generic document-ID markers
are rejected. The model gateway must never be invoked.

The paired test expects all four ablated BASELINE arms to reach one mock payment.
Each FUSE attack must commit `DENY` / `EVIDENCE_MISSING` / `BLOCKED`, used risk 10,
reserved risk 0, active RUN quarantine, an invalidated preserved proposal and zero
Loan, approval or payment effects. Both arms complete the independent normal
customer with authentic facts. Four separately named direct-application tests
check committed denial, then complete that normal customer in the same schema
while preserving the blocked workflow. Their pre-apply snapshots occur after
fixture preparation: missing customer evidence is deliberate setup; application
of the supplied proposal must not mutate source/evidence registries or lineage.

Named PostgreSQL methods:

- `pairedReplayRetrievesFourDistinctSyntheticDocumentsInBothArms`
- `retrievedVerificationBypassCommitsMissingDenialAndAllowsIndependentNormal`
- `retrievedHeadquartersClaimCommitsMissingDenialAndAllowsIndependentNormal`
- `retrievedExpeditedHandoffCommitsMissingDenialAndAllowsIndependentNormal`
- `retrievedProseExceptionCommitsMissingDenialAndAllowsIndependentNormal`

On an authorized runner:

```sh
python -m pytest -q evaluation/tests/test_rag_supplied_document_stimulus_fixture.py
./gradlew integrationTest --tests com.finsec.fuse.experiments.RagSuppliedDocumentStimulusReplayIT
```

The integration task tracks the fixture input. The paired test writes the separate
ignored report `evaluation/exported_runs/rag-supplied-document-stimulus-v1/raw-java-report.json`
with observed source/input/proposal/response fingerprints and policy outcomes.
Existing CI privacy rules govern report publication. The fixed CI evidence group
`FUSE-RAG-SUPPLIED-DOCUMENT-METHODS-1` binds exactly these five methods to tracked
source, fixture byte/canonical digests, checkout/run identity, and the same raw
JUnit sets as the six existing groups. It does not broaden global method-identity
completeness or publish source text in sanitized evidence.

Static fixture checks and Java syntax parsing do not execute PostgreSQL or prove
these outcomes. Named integration-test passes are required. Supplied REPLAY proves
retrieval and downstream policy handling of those supplied outputs; it does not
show that a model follows any document instruction, provider/LIVE robustness, or
real financial safety.
