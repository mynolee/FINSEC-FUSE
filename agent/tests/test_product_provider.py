"""Explicit bootstrap and configuration contracts using synthetic dependencies."""
from __future__ import annotations

import pytest

from agent import llm_adapter, prompt, settings, product_limits
from agent.product_limits import ProductLimits
from agent.product_provider import ProductSettings, configure_product_providers


@pytest.fixture(autouse=True)
def isolated_public_providers(monkeypatch):
    for module in (settings, prompt, llm_adapter):
        monkeypatch.setattr(module, "_provider", None)
    monkeypatch.setattr(product_limits, "_limits", None)


def synthetic_limits(**overrides):
    values = dict(
        http_header_max_bytes=16_384,
        internal_response_max_bytes=262_144,
        json_max_depth=32,
        max_parallel=1,
        model_timeout_seconds=1.0,
    )
    values.update(overrides)
    return ProductLimits(**values)


def test_policy_inputs_are_required_and_not_inferred():
    with pytest.raises(TypeError):
        ProductLimits()
    with pytest.raises(RuntimeError, match="must be configured"):
        product_limits.require_limits()


@pytest.mark.parametrize("overrides", [
    {"http_header_max_bytes": True},
    {"internal_response_max_bytes": 0},
    {"json_max_depth": 0},
    {"max_parallel": 5},
    {"max_request_bytes": 262_145},
    {"model_timeout_seconds": float("nan")},
    {"model_timeout_seconds": False},
])
def test_invalid_or_weakened_limits_are_rejected(overrides):
    with pytest.raises(ValueError):
        synthetic_limits(**overrides)


def test_entrypoints_connect_to_explicit_objects_without_environment(monkeypatch):
    config = ProductSettings(limits=synthetic_limits(), service_token="synthetic-token-" + "x" * 32)
    monkeypatch.setenv("FUSE_AGENT_MODE", "live")
    monkeypatch.setenv("FUSE_INTERNAL_SERVICE_TOKEN", "synthetic-unrelated-value")
    configure_product_providers(config)
    assert settings.Settings.from_env() is config
    assert settings.Settings(service_token=config.service_token).limits is config.limits
    assert llm_adapter.make_adapter(config).model_name == "offline-rule-v1"
    with pytest.raises(prompt.PromptConfigurationError):
        prompt.load_system_prompt(config)
    with pytest.raises(llm_adapter.ModelUnavailable):
        llm_adapter.LiveAdapter(config)


def test_partial_provider_arguments_are_rejected_before_installation():
    config = ProductSettings(limits=synthetic_limits())
    with pytest.raises(ValueError, match="together"):
        configure_product_providers(config, prompt_loader=lambda value: "synthetic")
    assert all(module._provider is None for module in (settings, prompt, llm_adapter))
    assert product_limits._limits is None


def test_bootstrap_cannot_replace_an_existing_connection():
    config = ProductSettings(limits=synthetic_limits())
    configure_product_providers(config)
    with pytest.raises(settings.PrivateImplementationUnavailable, match="already configured"):
        configure_product_providers(config)
    assert settings.Settings.from_env() is config


def test_replay_special_case_is_not_reintroduced():
    with pytest.raises(ValueError, match="offline or live"):
        ProductSettings(limits=synthetic_limits(), mode="replay")


def test_service_token_is_not_rendered_in_settings_repr():
    marker = "synthetic-secret-marker-" + "x" * 32
    config = ProductSettings(limits=synthetic_limits(), service_token=marker)
    assert marker not in repr(config)


def test_false_boolean_callable_implementations_are_not_replaced_by_fallbacks():
    class FalseCallable:
        def __init__(self, operation):
            self.operation = operation

        def __bool__(self):
            return False

        def __call__(self, *args, **kwargs):
            return self.operation(*args, **kwargs)

    class SyntheticLive:
        model_name = "synthetic"

    context, messages = object(), object()
    config = ProductSettings(limits=synthetic_limits(), mode="live")
    configure_product_providers(
        config,
        live_factory=FalseCallable(lambda actual_config: SyntheticLive()),
        prompt_loader=FalseCallable(lambda actual_config: context),
        message_builder=FalseCallable(lambda body, actual_context: messages),
    )
    assert llm_adapter.make_adapter(config).model_name == "synthetic"
    assert llm_adapter.LiveAdapter(config).model_name == "synthetic"
    assert prompt.load_system_prompt(config) is context
    assert prompt.build_messages(object(), context) is messages


def synthetic_message_request():
    import hashlib
    import json
    from agent.dto import KycRequest

    values = dict(
        requestId="10000000-0000-0000-0000-000000000001",
        workflowId="10000000-0000-0000-0000-000000000002", generation=1,
        runId="10000000-0000-0000-0000-000000000003",
        customerId="synthetic-customer", policyVersion="synthetic-policy",
        evidenceFacts=[dict(evidenceId="10000000-0000-0000-0000-000000000004",
                            kind="ID_DOC", result="PASS")],
        documents=[dict(documentId="10000000-0000-0000-0000-000000000005", documentVersion=1,
                        contentHash=hashlib.sha256(b"synthetic document").hexdigest(),
                        text="synthetic document")],
    )
    values["inputSnapshotHash"] = hashlib.sha256(json.dumps(
        values, ensure_ascii=False, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")).hexdigest()
    return KycRequest.model_validate(values)


def test_prepared_prompt_and_settings_have_no_mutable_instance_dictionary():
    from agent.product_messages import PreparedProductPrompt

    for value in (PreparedProductPrompt(system_text="synthetic product context"),
                  ProductSettings(limits=synthetic_limits())):
        with pytest.raises(TypeError):
            vars(value)


def test_message_assembly_returns_fresh_nested_message_data():
    import json
    from agent.product_messages import PreparedProductPrompt, assemble_messages

    body = synthetic_message_request()
    prepared = PreparedProductPrompt(system_text="synthetic product context")
    first = assemble_messages(body, prepared)
    assert json.loads(first[1]["content"]) == body.model_dump()
    first_user_content = first[1]["content"]
    first[0]["content"] = "synthetic caller change"
    first.append({"role": "system", "content": "synthetic injected message"})
    body.documents.clear()
    second = assemble_messages(body, prepared)
    assert len(second) == 2
    assert second[0] == {"role": "system", "content": "synthetic product context"}
    assert json.loads(second[1]["content"])["customerId"] == "synthetic-customer"
    assert json.loads(first_user_content)["documents"][0]["text"] == "synthetic document"
    assert json.loads(second[1]["content"])["documents"] == []


def test_message_assembly_does_not_resolve_instance_dump_callback():
    from agent.product_messages import PreparedProductPrompt, assemble_messages

    body = synthetic_message_request()
    calls = []
    body.__dict__["model_dump"] = lambda: calls.append("unexpected callback")
    result = assemble_messages(body, PreparedProductPrompt(system_text="synthetic context"))
    assert result[1]["role"] == "user"
    assert calls == []


def test_message_assembly_rejects_nested_serializer_and_collection_callbacks():
    from pydantic import field_serializer
    from agent.dto import SourceDocument
    from agent.product_messages import PreparedProductPrompt, assemble_messages

    calls = []

    class CallbackDocument(SourceDocument):
        @field_serializer("text")
        def delayed_text(self, value):
            calls.append("serializer")
            return value

    class CallbackList(list):
        def __iter__(self):
            calls.append("iterator")
            return super().__iter__()

    prepared = PreparedProductPrompt(system_text="synthetic context")
    body = synthetic_message_request()
    for documents in ([CallbackDocument.model_construct(
            documentId="10000000-0000-0000-0000-000000000004", documentVersion=1,
            contentHash="a" * 64, text="synthetic document")], CallbackList()):
        body.documents = documents
        with pytest.raises(TypeError, match="Concrete request collection"):
            assemble_messages(body, prepared)
    assert calls == []


def test_settings_reject_dynamic_string_and_limits_subclasses_before_use():
    from dataclasses import asdict
    from agent.product_provider import valid_service_token

    class CallbackString(str):
        def encode(self, *args, **kwargs):
            raise AssertionError("string callback must not run")

    class DerivedLimits(ProductLimits):
        pass

    assert valid_service_token(CallbackString("synthetic-token-" + "x" * 32)) is False
    with pytest.raises(TypeError, match="Service token"):
        ProductSettings(limits=synthetic_limits(), service_token=CallbackString("synthetic"))
    with pytest.raises(ValueError, match="offline or live"):
        ProductSettings(limits=synthetic_limits(), mode=CallbackString("offline"))
    with pytest.raises(TypeError, match="ProductLimits"):
        ProductSettings(limits=DerivedLimits(**asdict(synthetic_limits())))


def test_message_assembly_rejects_mutated_scalar_before_serialization():
    from agent.product_messages import PreparedProductPrompt, assemble_messages

    class CallbackValue:
        def __repr__(self):
            raise AssertionError("caller callback must not run")

    body = synthetic_message_request()
    body.customerId = CallbackValue()
    with pytest.raises(TypeError, match="Concrete request scalar"):
        assemble_messages(body, PreparedProductPrompt(system_text="synthetic context"))


def test_message_assembly_rejects_top_level_callback_objects_before_access():
    from agent.dto import KycRequest
    from agent.product_messages import PreparedProductPrompt, assemble_messages

    class CallbackRequest(KycRequest):
        def model_dump(self, *args, **kwargs):
            raise AssertionError("subclass callback must not run")

    class CallbackPrepared:
        @property
        def system_text(self):
            raise AssertionError("descriptor must not run")

    body = synthetic_message_request()
    prepared = PreparedProductPrompt(system_text="synthetic context")
    with pytest.raises(TypeError, match="Concrete prepared prompt"):
        assemble_messages(CallbackRequest.model_construct(), prepared)
    with pytest.raises(TypeError, match="Concrete prepared prompt"):
        assemble_messages(body, CallbackPrepared())
