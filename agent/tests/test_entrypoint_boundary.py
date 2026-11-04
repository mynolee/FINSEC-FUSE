"""Synthetic startup ordering: no model, listener, provider or environment lookup."""
import pytest

from agent import app, entrypoint
from agent.product_limits import ProductLimits
from agent.product_provider import ProductSettings


@pytest.fixture
def limits():
    return ProductLimits(
        http_header_max_bytes=1024, internal_response_max_bytes=4096,
        json_max_depth=8, max_parallel=1, model_timeout_seconds=1,
    )


@pytest.mark.parametrize("token", ["", "short", "CHANGE_ME", "x" * 32 + ",", "x" * 32 + " "])
def test_invalid_settings_fail_before_global_provider_registration(limits, monkeypatch, token):
    calls = []
    monkeypatch.setattr(entrypoint, "configure_product_providers", lambda *args, **kwargs: calls.append("configure"))
    config = ProductSettings(limits=limits, service_token=token)
    with pytest.raises(RuntimeError, match="^Internal service token is missing or invalid$") as failure:
        entrypoint.create_product_app(config)
    assert calls == []
    assert failure.value.__cause__ is None
    assert str(failure.value) == "Internal service token is missing or invalid"


def test_wrong_explicit_settings_type_fails_before_registration(monkeypatch):
    calls = []
    monkeypatch.setattr(entrypoint, "configure_product_providers", lambda *args, **kwargs: calls.append("configure"))
    with pytest.raises(TypeError, match="^An explicit ProductSettings object is required$"):
        entrypoint.create_product_app({"service_token": "synthetic"})
    assert calls == []


def test_direct_app_rejects_bad_settings_before_factory_or_adapter_descriptors(limits, monkeypatch):
    calls = []
    monkeypatch.setattr(app, "require_limits", lambda: limits)
    monkeypatch.setattr(app, "make_adapter", lambda config: calls.append("factory"))
    config = ProductSettings(limits=limits, service_token="short", mode="live")
    class Adapter:
        @property
        def capture(self):
            calls.append("capture descriptor")
            raise AssertionError("No adapter binding for invalid settings")
    for adapter in (None, Adapter()):
        with pytest.raises(RuntimeError, match="^Internal service token is missing or invalid$"):
            app.create_app(settings=config, adapter=adapter)
    assert calls == []


def test_valid_explicit_config_registration_still_delegates_construction(limits, monkeypatch):
    calls = []
    config = ProductSettings(limits=limits, service_token="synthetic-service-token-" + "v" * 32)
    sentinel = object()
    monkeypatch.setattr(entrypoint, "configure_product_providers", lambda actual, **kwargs: calls.append((actual, kwargs)))
    monkeypatch.setattr(app, "create_app", lambda **kwargs: sentinel)
    assert entrypoint.create_product_app(config) is sentinel
    assert calls == [(config, {"adapter_factory": None, "live_factory": None,
                              "prompt_loader": None, "message_builder": None})]
