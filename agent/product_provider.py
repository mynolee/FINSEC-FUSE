"""New product implementation connected through the preserved public boundaries.

Configuration and optional model/prompt callables must come from the caller.
No environment, prompt path, credential file, provider module, or network is read.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Any

from . import llm_adapter, prompt, settings
from .dto import KycProposal, KycRequest
from .product_limits import ProductLimits, configure_limits, require_limits


def valid_service_token(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        return (
            len(value.encode("utf-8")) >= 32
            and value != "CHANGE_ME"
            and not any(char.isspace() or char == "," for char in value)
        )
    except UnicodeError:
        return False


@dataclass(frozen=True, kw_only=True, slots=True)
class ProductSettings:
    limits: ProductLimits
    service_token: str = field(default="", repr=False)
    mode: str = "offline"

    def __post_init__(self):
        if type(self.limits) is not ProductLimits:
            raise TypeError("Explicit ProductLimits are required")
        if type(self.service_token) is not str:
            raise TypeError("Service token must be a string")
        if type(self.mode) is not str or self.mode not in ("offline", "live"):
            raise ValueError("Only explicit offline or live product mode is supported")

    @property
    def max_parallel(self) -> int:
        return self.limits.max_parallel

    @property
    def model_timeout_seconds(self) -> float:
        return self.limits.model_timeout_seconds

    @property
    def max_request_bytes(self) -> int:
        return self.limits.max_request_bytes

    def errors(self) -> tuple[str, ...]:
        return () if valid_service_token(self.service_token) else ("INVALID_SERVICE_TOKEN",)

    def system_prompt(self):
        return prompt.load_system_prompt(self)


class OfflineRuleAdapter:
    """Proposal-only evidence rule; document text is never an authority source."""

    model_name = "offline-rule-v1"

    def __init__(self, config: ProductSettings):
        if config.mode != "offline":
            raise llm_adapter.ModelUnavailable("Offline adapter requires offline mode")

    async def propose(self, request: KycRequest) -> KycProposal:
        facts = request.evidenceFacts
        identifiers = [fact.evidenceId for fact in facts]
        passed_kinds = {fact.kind for fact in facts if fact.result == "PASS"}
        verified = (
            passed_kinds == {"ID_DOC", "FACE_MATCH"}
            and all(fact.result == "PASS" for fact in facts)
            and len(identifiers) == len(set(identifiers))
        )
        return KycProposal(
            status="VERIFIED" if verified else "NOT_VERIFIED",
            evidenceIds=identifiers if verified else [],
            explanation="Required evidence facts passed." if verified
            else "Required evidence facts are missing, failed, or ambiguous.",
        )


def _prompt_unavailable(*args, **kwargs):
    raise prompt.PromptConfigurationError("An explicit prompt provider is required")


def _live_unavailable(*args, **kwargs):
    raise llm_adapter.ModelUnavailable("An explicit live adapter is required")


def configure_product_providers(
    config: ProductSettings,
    *,
    adapter_factory: Callable[[ProductSettings], Any] | None = None,
    live_factory: Callable[..., Any] | None = None,
    prompt_loader: Callable[..., Any] | None = None,
    message_builder: Callable[..., Any] | None = None,
) -> None:
    """Bind one explicit product configuration before starting serving threads.

    The from_env compatibility entry returns this bound object; it does not
    inspect ambient environment variables. Live transport and message composition
    exist only when the caller supplies explicit implementations.
    """
    if type(config) is not ProductSettings:
        raise TypeError("An explicit ProductSettings object is required")
    for callback in (adapter_factory, live_factory, prompt_loader, message_builder):
        if callback is not None and not callable(callback):
            raise TypeError("Explicit provider implementations must be callable")
    if (prompt_loader is None) != (message_builder is None):
        raise ValueError("Prompt loader and builder must be supplied together")
    # These preserved boundary modules expose one startup registration each.
    # Preflight avoids an expected partial registration; startup is single-threaded.
    if any(module._provider is not None for module in (settings, prompt, llm_adapter)):
        raise settings.PrivateImplementationUnavailable("Product providers are already configured")
    try:
        require_limits()
    except RuntimeError:
        pass
    else:
        raise settings.PrivateImplementationUnavailable("Product limits are already configured")

    def constructor(*args, **kwargs):
        actual_limits = kwargs.pop("limits", config.limits)
        if actual_limits is not config.limits:
            raise ValueError("Settings must use the explicitly configured product limits")
        return ProductSettings(*args, limits=actual_limits, **kwargs)

    def configured_settings(*args, **kwargs):
        if args or kwargs:
            raise TypeError("The bound settings entry accepts no environment overrides")
        return config

    def factory(actual_config):
        if adapter_factory is not None:
            return adapter_factory(actual_config)
        if actual_config.mode == "offline":
            return OfflineRuleAdapter(actual_config)
        return (live_factory if live_factory is not None else _live_unavailable)(actual_config)

    configure_limits(config.limits)
    settings.configure_settings_provider(constructor=constructor, from_env=configured_settings)
    prompt.configure_prompt_provider(
        loader=prompt_loader if prompt_loader is not None else _prompt_unavailable,
        builder=message_builder if message_builder is not None else _prompt_unavailable,
        configuration_errors=(),
    )
    llm_adapter.configure_adapter_provider(
        factory=factory,
        live_factory=live_factory if live_factory is not None else _live_unavailable,
        model_output_invalid=(),
        model_unavailable=(),
        private_documents_unavailable=(),
    )
