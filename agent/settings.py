"""Public settings connection; configure the private provider before importing app.

This module owns no settings defaults, environment mapping, or validation policy.
The provider receives every argument and returns the original settings object.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


class PrivateImplementationUnavailable(RuntimeError):
    """An explicitly required private provider has not been configured."""


@dataclass(frozen=True)
class _SettingsProvider:
    constructor: Callable[..., Any]
    from_env: Callable[..., Any]


_provider: _SettingsProvider | None = None


def configure_settings_provider(
    *, constructor: Callable[..., Any], from_env: Callable[..., Any]
) -> None:
    """Install explicit callables once, during startup before serving requests."""
    global _provider
    if not callable(constructor) or not callable(from_env):
        raise TypeError("Settings provider functions must be callable")
    if _provider is not None:
        raise PrivateImplementationUnavailable("Settings provider is already configured")
    _provider = _SettingsProvider(constructor, from_env)


def _require_provider() -> _SettingsProvider:
    if _provider is None:
        raise PrivateImplementationUnavailable(
            "Private settings provider is required; call configure_settings_provider "
            "before importing agent.app"
        )
    return _provider


class Settings:
    """Preserve constructor/from_env calls by returning the provider's object.

    Concrete type identity, reflection, and serialization belong to that provider.
    """

    def __new__(cls, *args: Any, **kwargs: Any) -> Any:
        return _require_provider().constructor(*args, **kwargs)

    @classmethod
    def from_env(cls, *args: Any, **kwargs: Any) -> Any:
        return _require_provider().from_env(*args, **kwargs)
