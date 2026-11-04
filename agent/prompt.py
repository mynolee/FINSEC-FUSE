"""Explicit connections to private prompt loading and message construction.

No prompt text, composition rules, path discovery, or fallback is defined here.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .settings import PrivateImplementationUnavailable


class PromptConfigurationError(Exception):
    """The configured prompt provider rejected its configuration."""


@dataclass(frozen=True)
class _PromptProvider:
    loader: Callable[..., Any]
    builder: Callable[..., Any]
    configuration_errors: tuple[type[Exception], ...]


_provider: _PromptProvider | None = None


def configure_prompt_provider(
    *,
    loader: Callable[..., Any],
    builder: Callable[..., Any],
    configuration_errors: tuple[type[Exception], ...],
) -> None:
    """Install callables and their private configuration exception types once.

    Use an explicit empty tuple if the provider already raises the public error.
    Exception arguments are passed through; this connection does not redact them.
    """
    global _provider
    if not callable(loader) or not callable(builder):
        raise TypeError("Prompt provider functions must be callable")
    if not isinstance(configuration_errors, tuple) or any(
        not isinstance(error, type) or not issubclass(error, Exception)
        for error in configuration_errors
    ):
        raise TypeError("Prompt configuration errors must be a tuple of exception types")
    if _provider is not None:
        raise PrivateImplementationUnavailable("Prompt provider is already configured")
    _provider = _PromptProvider(loader, builder, configuration_errors)


def _require_provider() -> _PromptProvider:
    if _provider is None:
        raise PrivateImplementationUnavailable(
            "Private prompt provider is required; call configure_prompt_provider "
            "before importing agent.app"
        )
    return _provider


def _invoke(operation: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    provider = _require_provider()
    try:
        return operation(*args, **kwargs)
    except PromptConfigurationError:
        raise
    except provider.configuration_errors as error:
        raise PromptConfigurationError(*error.args) from error


def load_system_prompt(*args: Any, **kwargs: Any) -> Any:
    """Forward the existing loader call without reading paths in this module."""
    return _invoke(_require_provider().loader, *args, **kwargs)


def build_messages(*args: Any, **kwargs: Any) -> Any:
    """Forward the existing message-builder call and return its exact result."""
    return _invoke(_require_provider().builder, *args, **kwargs)
