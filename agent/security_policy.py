"""Read the same versioned, operator-owned policy as the Java boundary."""
import json
import os
from pathlib import Path

_PATH = Path(os.getenv("FUSE_SECURITY_POLICY_PATH", str(Path(__file__).resolve().parents[1] /
    "backend/src/main/resources/config/security_policy.json")))
with _PATH.open("rb") as source:
    _raw = source.read(16_385)
if len(_raw) > 16_384:
    raise ValueError("security policy exceeds bound")
POLICY = json.loads(_raw)
if POLICY.get("policyVersion") != "FUSE-SECURITY-1":
    raise ValueError("unsupported security policy")
_EXPECTED = {"internalRequestMaxBytes": 262144, "internalResponseMaxBytes": 65536,
             "jsonMaxDepth": 16, "evidenceFactsMaxItems": 10, "documentsMaxItems": 8,
             "documentTextMaxUtf8Bytes": 16384, "modelConcurrency": 4, "httpHeaderMaxBytes": 16384}
if any(type(POLICY.get(key)) is not int or POLICY[key] != value for key, value in _EXPECTED.items()):
    raise ValueError("invalid security policy")
