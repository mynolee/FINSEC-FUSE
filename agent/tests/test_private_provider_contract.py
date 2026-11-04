"""Synthetic connection contracts; no private implementation or data is used.

These tests deliberately do not import agent.app, whose deployment bootstrap must
configure providers before its existing module-level create_app call.
"""
from __future__ import annotations

import asyncio

import pytest

from agent import llm_adapter, prompt, settings


@pytest.fixture(autouse=True)
def isolated_providers(monkeypatch):
    for module in (settings, prompt, llm_adapter):
        monkeypatch.setattr(module, "_provider", None)


def configure_adapter(factory, live_factory, *, invalid=(), unavailable=(), documents=()):
    llm_adapter.configure_adapter_provider(
        factory=factory,
        live_factory=live_factory,
        model_output_invalid=invalid,
        model_unavailable=unavailable,
        private_documents_unavailable=documents,
    )


@pytest.mark.parametrize("operation", [
    lambda: settings.Settings(),
    lambda: settings.Settings.from_env(),
    lambda: prompt.load_system_prompt(object()),
    lambda: prompt.build_messages(object(), object()),
    lambda: llm_adapter.make_adapter(object()),
    lambda: llm_adapter.LiveAdapter(object()),
])
def test_missing_provider_fails_with_configuration_error(operation):
    with pytest.raises(settings.PrivateImplementationUnavailable, match="provider is required"):
        operation()


def test_settings_constructor_and_from_env_forward_arguments_and_exact_objects():
    calls, configured, from_environment = [], object(), object()

    def constructor(*args, **kwargs):
        calls.append(("constructor", args, kwargs))
        return configured

    def from_env(*args, **kwargs):
        calls.append(("from_env", args, kwargs))
        return from_environment

    settings.configure_settings_provider(constructor=constructor, from_env=from_env)
    marker = object()
    assert settings.Settings(marker, explicit=marker) is configured
    assert settings.Settings.from_env(marker, explicit=marker) is from_environment
    assert calls == [
        ("constructor", (marker,), {"explicit": marker}),
        ("from_env", (marker,), {"explicit": marker}),
    ]


def test_settings_provider_exception_is_unchanged_and_not_retried():
    failure, calls = ValueError("synthetic"), []

    def fail(*args, **kwargs):
        calls.append(1)
        raise failure

    settings.configure_settings_provider(constructor=fail, from_env=fail)
    with pytest.raises(ValueError) as caught:
        settings.Settings()
    assert caught.value is failure
    assert calls == [1]


@pytest.mark.parametrize("module,configure", [
    (settings, lambda factory: settings.configure_settings_provider(
        constructor=factory, from_env=factory)),
    (prompt, lambda factory: prompt.configure_prompt_provider(
        loader=factory, builder=factory, configuration_errors=())),
    (llm_adapter, lambda factory: configure_adapter(factory, factory)),
])
def test_provider_cannot_be_replaced_after_configuration(module, configure):
    configure(lambda *args, **kwargs: object())
    original = module._provider
    with pytest.raises(settings.PrivateImplementationUnavailable, match="already configured"):
        configure(lambda *args, **kwargs: object())
    assert module._provider is original


def test_prompt_loader_and_builder_return_exact_results_without_transforming_arguments():
    calls, loaded, messages = [], object(), object()

    def loader(*args, **kwargs):
        calls.append(("loader", args, kwargs))
        return loaded

    def builder(*args, **kwargs):
        calls.append(("builder", args, kwargs))
        return messages

    prompt.configure_prompt_provider(loader=loader, builder=builder, configuration_errors=())
    marker = object()
    assert prompt.load_system_prompt(marker, explicit=marker) is loaded
    assert prompt.build_messages(marker, loaded, explicit=marker) is messages
    assert calls == [
        ("loader", (marker,), {"explicit": marker}),
        ("builder", (marker, loaded), {"explicit": marker}),
    ]


def test_private_prompt_error_preserves_arguments_and_cause_without_retry():
    class PrivatePromptError(Exception):
        pass

    marker, calls = object(), []
    failure = PrivatePromptError("synthetic", marker)

    def fail(*args, **kwargs):
        calls.append(1)
        raise failure

    prompt.configure_prompt_provider(
        loader=fail, builder=fail, configuration_errors=(PrivatePromptError,)
    )
    with pytest.raises(prompt.PromptConfigurationError) as caught:
        prompt.build_messages(object(), object())
    assert caught.value.args == failure.args
    assert caught.value.__cause__ is failure
    assert calls == [1]


@pytest.mark.parametrize("error_type", [prompt.PromptConfigurationError, LookupError])
def test_public_or_unregistered_prompt_errors_keep_identity(error_type):
    failure = error_type("synthetic")

    def fail(*args, **kwargs):
        raise failure

    prompt.configure_prompt_provider(loader=fail, builder=fail, configuration_errors=())
    with pytest.raises(error_type) as caught:
        prompt.load_system_prompt(object())
    assert caught.value is failure


def test_adapter_factories_are_distinct_and_proposal_result_is_unchanged():
    calls, result, marker = [], object(), object()

    class Source:
        model_name = "synthetic-model"

        async def propose(self, *args, **kwargs):
            calls.append(("propose", args, kwargs))
            return result

    def factory(*args, **kwargs):
        calls.append(("factory", args, kwargs))
        return Source()

    def live_factory(*args, **kwargs):
        calls.append(("live_factory", args, kwargs))
        return Source()

    configure_adapter(factory, live_factory)
    connected = llm_adapter.make_adapter(marker, explicit=marker)
    live = llm_adapter.LiveAdapter(marker, explicit=marker)
    assert connected.model_name == "synthetic-model"
    assert live.model_name == "synthetic-model"
    assert asyncio.run(connected.propose(marker, explicit=marker)) is result
    assert calls == [
        ("factory", (marker,), {"explicit": marker}),
        ("live_factory", (marker,), {"explicit": marker}),
        ("propose", (marker,), {"explicit": marker}),
    ]
    assert not hasattr(connected, "capture")


def test_optional_capture_preserves_exact_tuple_and_call_arguments():
    marker, result, calls = object(), (object(), "synthetic-model"), []

    class Source:
        async def capture(self, *args, **kwargs):
            calls.append((args, kwargs))
            return result

    configure_adapter(lambda value: Source(), lambda value: Source())
    connected = llm_adapter.LiveAdapter(marker)
    assert callable(getattr(connected, "capture", None))
    assert asyncio.run(connected.capture(marker, explicit=marker)) is result
    assert calls == [((marker,), {"explicit": marker})]


def test_noncallable_capture_remains_noncallable():
    class Source:
        capture = None

    configure_adapter(lambda: Source(), lambda: Source())
    assert llm_adapter.make_adapter().capture is None


@pytest.mark.parametrize("family,public_error", [
    ("invalid", llm_adapter.ModelOutputInvalid),
    ("unavailable", llm_adapter.ModelUnavailable),
    ("documents", llm_adapter.PrivateDocumentsUnavailable),
])
@pytest.mark.parametrize("stage", ["factory", "propose", "capture"])
def test_registered_private_adapter_errors_preserve_category_args_and_single_attempt(
    family, public_error, stage
):
    class PrivateError(Exception):
        pass

    calls, marker = [], object()
    failure = PrivateError("synthetic", marker)

    async def fail(*args, **kwargs):
        calls.append(1)
        raise failure

    class Source:
        propose = staticmethod(fail)
        capture = staticmethod(fail)

    def factory():
        if stage == "factory":
            calls.append(1)
            raise failure
        return Source()

    configure_adapter(factory, factory, **{family: (PrivateError,)})
    with pytest.raises(public_error) as caught:
        connected = llm_adapter.make_adapter()
        asyncio.run(getattr(connected, stage)(marker))
    assert caught.value.args == failure.args
    assert caught.value.__cause__ is failure
    assert calls == [1]


@pytest.mark.parametrize("error_type", [
    llm_adapter.ModelOutputInvalid,
    llm_adapter.ModelUnavailable,
    llm_adapter.PrivateDocumentsUnavailable,
    TimeoutError,
    LookupError,
    asyncio.CancelledError,
])
def test_canonical_unregistered_and_cancellation_errors_keep_identity(error_type):
    failure, calls = error_type("synthetic"), []

    class Source:
        async def propose(self, request):
            calls.append(1)
            raise failure

    configure_adapter(lambda: Source(), lambda: Source())
    async def check():
        with pytest.raises(error_type) as caught:
            await llm_adapter.make_adapter().propose(object())
        assert caught.value is failure

    asyncio.run(check())
    assert calls == [1]


def test_overlapping_private_adapter_exception_families_are_rejected_atomically():
    class PrivateParent(Exception):
        pass

    class PrivateChild(PrivateParent):
        pass

    with pytest.raises(TypeError, match="must not overlap"):
        configure_adapter(lambda: object(), lambda: object(),
                          invalid=(PrivateParent,), unavailable=(PrivateChild,))
    with pytest.raises(settings.PrivateImplementationUnavailable):
        llm_adapter.make_adapter()


@pytest.mark.parametrize("configure", [
    lambda: settings.configure_settings_provider(constructor=None, from_env=lambda: object()),
    lambda: prompt.configure_prompt_provider(loader=None, builder=lambda: object(),
                                            configuration_errors=()),
    lambda: prompt.configure_prompt_provider(loader=lambda: object(), builder=lambda: object(),
                                            configuration_errors=(object,)),
    lambda: configure_adapter(None, lambda: object()),
    lambda: configure_adapter(lambda: object(), lambda: object(), invalid=(BaseException,)),
])
def test_invalid_provider_registration_is_rejected_before_installation(configure):
    with pytest.raises(TypeError):
        configure()
    assert settings._provider is None
    assert prompt._provider is None
    assert llm_adapter._provider is None


@pytest.mark.parametrize("attribute", ["model_name", "propose", "capture"])
def test_private_adapter_attribute_errors_use_registered_public_category(attribute):
    class PrivateError(Exception):
        pass

    failure, calls = PrivateError("synthetic"), []

    def fail_getter(self):
        calls.append(1)
        raise failure

    class Source:
        pass

    setattr(Source, attribute, property(fail_getter))
    configure_adapter(lambda: Source(), lambda: Source(), unavailable=(PrivateError,))
    connected = llm_adapter.make_adapter()
    with pytest.raises(llm_adapter.ModelUnavailable) as caught:
        if attribute == "propose":
            asyncio.run(connected.propose(object()))
        else:
            getattr(connected, attribute)
    assert caught.value.args == failure.args
    assert caught.value.__cause__ is failure
    assert calls == [1]


def test_broad_private_error_family_does_not_invent_optional_capture():
    class Source:
        pass

    configure_adapter(lambda: Source(), lambda: Source(), invalid=(Exception,))
    assert getattr(llm_adapter.make_adapter(), "capture", None) is None


def test_ambiguous_multiple_inheritance_fails_with_explicit_configuration_error():
    class PrivateInvalid(Exception):
        pass

    class PrivateUnavailable(Exception):
        pass

    class AmbiguousError(PrivateInvalid, PrivateUnavailable):
        pass

    failure, calls = AmbiguousError("synthetic"), []

    class Source:
        async def propose(self, request):
            calls.append(1)
            raise failure

    configure_adapter(lambda: Source(), lambda: Source(),
                      invalid=(PrivateInvalid,), unavailable=(PrivateUnavailable,))
    with pytest.raises(settings.PrivateImplementationUnavailable,
                       match="multiple public error families") as caught:
        asyncio.run(llm_adapter.make_adapter().propose(object()))
    assert caught.value.__cause__ is failure
    assert calls == [1]



def test_unregistered_model_name_attribute_error_preserves_identity_args_and_message():
    failure = AttributeError("synthetic original getter failure", "synthetic detail")
    original_message, calls = str(failure), []

    class Source:
        @property
        def model_name(self):
            calls.append(1)
            raise failure

    configure_adapter(lambda: Source(), lambda: Source())
    connected = llm_adapter.make_adapter()
    with pytest.raises(AttributeError) as caught:
        connected.model_name
    assert caught.value is failure
    assert caught.value.args == ("synthetic original getter failure", "synthetic detail")
    assert str(caught.value) == original_message
    assert calls == [1]
