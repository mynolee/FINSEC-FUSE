"""Explicit product limits; no policy file or environment is inspected."""
from __future__ import annotations

import math
from dataclasses import dataclass
from types import MappingProxyType


# These bounds appear in the reviewed ordinary DTO/schema and HTTP test.
DTO_LIMITS = MappingProxyType({
    "documentTextMaxUtf8Bytes": 16_384,
    "evidenceFactsMaxItems": 10,
    "documentsMaxItems": 8,
})
REQUEST_MAX_BYTES = 262_144


@dataclass(frozen=True, kw_only=True, slots=True)
class ProductLimits:
    """Required operator choices; absent policy has no automatic defaults."""

    http_header_max_bytes: int
    internal_response_max_bytes: int
    json_max_depth: int
    max_parallel: int
    model_timeout_seconds: float
    max_request_bytes: int = REQUEST_MAX_BYTES

    def __post_init__(self):
        for value in (
            self.http_header_max_bytes, self.internal_response_max_bytes,
            self.json_max_depth, self.max_parallel, self.max_request_bytes,
        ):
            if type(value) is not int or value < 1:
                raise ValueError("Product byte, depth, and admission limits must be positive integers")
        if self.max_request_bytes > REQUEST_MAX_BYTES:
            raise ValueError("Request limit must not exceed the reviewed HTTP contract")
        if self.max_parallel > 4:
            raise ValueError("Parallel limit must not exceed the reviewed admission contract")
        timeout = self.model_timeout_seconds
        try:
            valid_timeout = (type(timeout) in (int, float)
                             and math.isfinite(timeout) and timeout > 0)
        except OverflowError:
            valid_timeout = False
        if not valid_timeout:
            raise ValueError("Model timeout must be finite and positive")


_limits: ProductLimits | None = None


def configure_limits(limits: ProductLimits) -> None:
    global _limits
    if type(limits) is not ProductLimits:
        raise TypeError("Explicit ProductLimits are required")
    # Validate again at the binding boundary, before resource calculations use it.
    ProductLimits.__post_init__(limits)
    if _limits is not None:
        raise RuntimeError("Product limits are already configured")
    _limits = limits


def require_limits() -> ProductLimits:
    if _limits is None:
        raise RuntimeError("Explicit product limits must be configured")
    return _limits
