"""Run registered fixtures through Java. No Python path writes payment rows."""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid

import httpx

from agent.dto import KycRequest
from agent.llm_adapter import make_adapter
from agent.prompt import PROMPT_VERSION, build_messages
from agent.settings import Settings
from .fixture_loader import load_fixture_set, fingerprint
from .metrics import calculate_metrics
from .report import CaseOutput, EvaluationReport
from .private_documents import load_private_documents, resolve_document


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # These ignored diagnostics may contain candidate text. Never create public-readable files.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n")


def model_request(case: dict, documents: dict[str, str] | None = None) -> KycRequest:
    customer = case["customerId"]
    customer_number = int(customer.rsplit("-", 1)[1])
    variant = case["evidenceVariant"]
    facts = [] if variant in {"missing", "wrong_customer"} else [
        {"evidenceId": f"00000000-0000-4000-8000-{customer_number * 10 + n:012d}", "kind": kind, "result": "PASS"}
        for n, kind in [(1, "ID_DOC"), (2, "FACE_MATCH")]]
    if variant == "missing_face": facts = facts[:1]
    # Revocation/hash integrity are authoritative DB properties absent from this
    # deliberately limited agent DTO; only Java can decide their validity.
    document_id = case["injection"]["parameters"].get("documentTextId", "reference-default")
    text = resolve_document(document_id, documents) if documents is not None else f"FUSE_DOCUMENT_ID:{document_id}"
    stable_id = lambda suffix: str(uuid.uuid5(uuid.NAMESPACE_URL, f"finsec:{case['caseId']}:{suffix}"))
    body = {"requestId": stable_id("request"), "workflowId": stable_id("workflow"), "generation": 1,
            "runId": stable_id("run"), "customerId": customer, "policyVersion": "FUSE-MVP-2",
            "evidenceFacts": facts, "documents": [{"documentId": "00000000-0000-4000-8000-000000000201",
            "documentVersion": case["documentVersion"], "contentHash": hashlib.sha256(text.encode()).hexdigest(), "text": text}]}
    body["inputSnapshotHash"] = hashlib.sha256(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    return KycRequest.model_validate(body)


async def prompt_audit(manifest: dict, mode: str, repeat_count: int) -> dict:
    """Audit prompt construction/candidate schema only, NOT financial controls."""
    configured = Settings.from_env(mode=mode)
    settings = Settings(service_token=configured.service_token, mode=mode, model=configured.model,
                        api_key=configured.api_key, base_url=configured.base_url,
                        prompt_path=configured.prompt_path, private_documents_path=configured.private_documents_path)
    errors = settings.errors()
    if errors:
        raise ValueError("; ".join(errors))
    adapter = make_adapter(settings)
    documents = load_private_documents(settings.private_documents_path) if mode == "live" else None
    # Validate all selected assets before starting any paid generation.
    requests = [(case, model_request(case, documents)) for case in manifest["cases"]]
    outputs = []
    for case, request in requests:
        for repeat in range(1, repeat_count + 1):
            started = time.perf_counter()
            try:
                async with asyncio.timeout(settings.model_timeout_seconds):
                    answer = await adapter.propose(request)
                outputs.append({"caseId": case["caseId"], "repeat": repeat,
                    "injectionSource": case["injection"]["source"], "requestHash": request.inputSnapshotHash,
                    "promptHash": fingerprint(build_messages(request, settings.system_prompt())) if mode == "live" else None,
                    "model": adapter.model_name,
                    "modelOutput": answer.model_dump(), "modelOutputHash": fingerprint(answer.model_dump()),
                    "elapsedMs": round((time.perf_counter()-started)*1000, 3), "status": "COMPLETED"})
            except Exception as exc:
                # Exception type only: a provider may echo credentials or contents.
                outputs.append({"caseId": case["caseId"], "repeat": repeat,
                    "status": "ERROR", "errorType": type(exc).__name__})
    return {"reportVersion": "FUSE-PROMPT-AUDIT-1", "createdAt": datetime.now(timezone.utc).isoformat(),
            "fixtureSetId": manifest["fixtureSetId"], "fixtureHash": manifest["fixtureHash"],
            "resultsSource": "PROMPT_ONLY", "modelMode": mode.upper(), "syntheticModelOutputs": mode != "live",
            "liveRobustnessMeasured": False, "promptVersion": PROMPT_VERSION,
            "systemPromptHash": hashlib.sha256(settings.system_prompt().encode()).hexdigest() if mode == "live" else None,
            "privatePromptLoaded": mode == "live", "caseOutputs": outputs,
            "limitations": ["No Java policy, PostgreSQL state, approvals, delegations, or payments were exercised.",
                "Deterministic offline/replay outcomes are not live LLM robustness measurements.",
                "Offline/replay uses opaque document IDs and does not load or fingerprint private prompt contents.",
                "Non-RAG injections require the Java scenario harness and are not exercised by this prompt-only audit.",
                "No forbidden-action block rate is calculated for this audit."]}


def execute_java(manifest: dict, base_url: str, token: str, model_mode: str, repeats: int,
                 output_dir: Path, deadline_seconds: float = 600) -> dict:
    if not token or token == "CHANGE_ME":
        raise ValueError("FUSE_DEVELOPER_TOKEN must be configured")
    # Local test endpoint by default; never forward the token through redirects.
    with httpx.Client(base_url=base_url.rstrip("/"), timeout=httpx.Timeout(35, connect=2),
                      follow_redirects=False, trust_env=False,
                      headers={"Authorization": f"Bearer {token}"}) as client:
        body = {"fixtureSetId": manifest["fixtureSetId"], "caseIds": [c["caseId"] for c in manifest["cases"]],
                "mode": "PAIRED", "modelMode": model_mode, "repeatCount": repeats}
        # Preserve the action ID if the HTTP result becomes uncertain. A failed
        # submission is not retried automatically with a fresh ID.
        action_id = str(uuid.uuid4())
        write_json(output_dir / "request.json", {"actionId": action_id, "body": body,
            "fixtureHash": manifest["fixtureHash"], "notice": "No credentials included."})
        response = client.post("/api/v1/experiments", json=body, headers={"Idempotency-Key": action_id})
        response.raise_for_status()
        accepted = response.json()
        write_json(output_dir / "accepted.json", accepted)
        experiment_id = accepted["experimentId"]
        deadline = time.monotonic() + deadline_seconds
        while True:
            response = client.get(f"/api/v1/experiments/{experiment_id}")
            response.raise_for_status()
            result = response.json()
            write_json(output_dir / "raw-java-report.json", result)
            if result.get("status") in {"COMPLETED", "FAILED", "INTERRUPTED", "SUCCEEDED"}:
                return result
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Experiment {experiment_id} still running; use GET /api/v1/experiments/{experiment_id} to resume observation. No completion claimed.")
            time.sleep(0.25)


def normalize_java_report(raw: dict, manifest: dict, model_mode: str, repeats: int) -> EvaluationReport:
    if raw.get("resultsSource") != "JAVA_POSTGRES_EXECUTION":
        raise ValueError("Backend did not attest Java/PostgreSQL execution; raw report retained without security metrics")
    if raw.get("modelMode") != model_mode:
        raise ValueError("Backend model mode does not match the requested evaluation mode")
    if model_mode == "LIVE" and (raw.get("syntheticModelOutputs") is not False or repeats != 3):
        raise ValueError("LIVE requires non-synthetic backend attestation and exactly three repeats")
    if model_mode == "REPLAY" and repeats != 1:
        raise ValueError("REPLAY requires exactly one repeat")
    source_version = raw.get("reportVersion", "UNSPECIFIED")
    if source_version not in {"UNSPECIFIED", "FUSE-EVALUATION-1", "FUSE-EVALUATION-2"}:
        raise ValueError("Unsupported backend report version; raw report retained")
    rows = [CaseOutput.model_validate(row) for row in raw["caseOutputs"]]
    for row in rows:
        if row.fixtureHash != manifest["fixtureHash"]:
            row.exclusionReason = "UNPAIRED_CONFIGURATION"
        elif source_version != "FUSE-EVALUATION-2" and not row.exclusionReason:
            row.exclusionReason = "PAIRED_INPUT_REPORT_VERSION_UNSUPPORTED"
    metrics = calculate_metrics(manifest["cases"], rows, repeats, model_mode)
    complete = raw["status"] in {"COMPLETED", "SUCCEEDED"}
    return EvaluationReport(inputReportVersion=source_version,experimentId=raw["experimentId"], fixtureSetId=manifest["fixtureSetId"],
        fixtureHash=manifest["fixtureHash"], status="COMPLETED" if complete else raw["status"],
        modelMode=model_mode, resultsSource="JAVA_POSTGRES_EXECUTION", syntheticModelOutputs=model_mode == "REPLAY",
        liveRobustnessMeasured=raw["status"] == "COMPLETED" and model_mode == "LIVE" and metrics["commonEligibleAttackPairs"] > 0,
        plannedCaseIds=[c["caseId"] for c in manifest["cases"]], repeatCount=repeats, caseOutputs=rows, metrics=metrics,
        limitations=["Replay measures policy behavior against synthetic candidates, not live LLM attack susceptibility.",
                     "Mock reviewer follows fixed APPROVE_IF_VERIFIED_AND_RECOMMENDED rule in both environments.",
                     "Payments are local mock ledger entries, never real transfers.",
                     "Unsupported injections, model failures, environment errors and unpaired outputs are excluded in both arms."])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["validate-fixtures", "prompt-audit", "run"])
    parser.add_argument("--fixture-set", default="security-evaluation-v1")
    parser.add_argument("--case-id", action="append", default=[])
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--model-mode", choices=["REPLAY", "OFFLINE", "LIVE"], default="REPLAY")
    parser.add_argument("--repeat-count", type=int, default=None)
    parser.add_argument("--allow-live", action="store_true", help="Explicitly authorize configured provider calls (may incur charges)")
    parser.add_argument("--output", type=Path, default=Path("evaluation/exported_runs"))
    args = parser.parse_args(argv)
    try:
        manifest = load_fixture_set(args.fixture_set, args.case_id)
        repeats = args.repeat_count if args.repeat_count is not None else (3 if args.model_mode == "LIVE" else 1)
        if repeats < 1 or repeats > 10: raise ValueError("repeat count must be 1..10")
        if args.model_mode == "REPLAY" and repeats != 1:
            raise ValueError("REPLAY requires exactly one repeat")
        if args.model_mode == "LIVE" and (not args.allow_live or repeats != 3):
            raise ValueError("LIVE requires --allow-live and exactly three repeats per case")
        if args.command == "validate-fixtures":
            print(json.dumps({"fixtureSetId": args.fixture_set, "fixtureHash": manifest["fixtureHash"],
                              "cases": len(manifest["cases"]), "status": "VALIDATED_PLAN_ONLY"}))
            return 0
        if args.command == "prompt-audit":
            report = asyncio.run(prompt_audit(manifest, args.model_mode.lower(), repeats))
            write_json(args.output / "prompt-audit.json", report)
            print(f"Prompt-only audit saved to {args.output / 'prompt-audit.json'}; no financial policy effectiveness measured.")
            return int(any(row["status"] == "ERROR" for row in report["caseOutputs"]))
        if args.model_mode == "OFFLINE":
            raise ValueError("Java experiments use REPLAY or LIVE; OFFLINE is for prompt-audit only")
        raw = execute_java(manifest, args.base_url, os.getenv("FUSE_DEVELOPER_TOKEN", ""), args.model_mode, repeats, args.output)
        report = normalize_java_report(raw, manifest, args.model_mode, repeats)
        write_json(args.output / "report.json", report.model_dump())
        from .export import export_evidence_bundle
        export_evidence_bundle(report, manifest, args.output)
        # Backend reason strings can contain private input; stdout is not a private report.
        print(json.dumps({"completed": report.status == "COMPLETED",
                          "caseOutputCount": len(report.caseOutputs),
                          "hasExcludedPairs": report.metrics["excludedPairCount"] != 0,
                          "evidenceBundleSaved": True}))
        return 0 if report.status == "COMPLETED" and report.metrics["excludedPairCount"] == 0 else 2
    except (ValueError, KeyError, TimeoutError, httpx.HTTPError) as exc:
        print(f"Evaluation not completed ({type(exc).__name__}); inspect private local diagnostics.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
