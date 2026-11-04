"""Public adapter contracts and explicit private-provider connection.

This module contains no provider selection, model defaults, transport, replay,
private-document loading, retries, or model-output processing.
"""
from __future__ import annotations

from dataclasses import dataclass
import inspect
from typing import TYPE_CHECKING, Any, Callable, Protocol

from .settings import PrivateImplementationUnavailable

if TYPE_CHECKING:
    from .dto import KycProposal, KycRequest


class ModelOutputInvalid(Exception):
    """The private adapter could not produce an accepted model output."""


class ModelUnavailable(Exception):
    """The private adapter could not complete the model operation."""


class PrivateDocumentsUnavailable(Exception):
    """The private adapter could not obtain required private documents."""


class Adapter(Protocol):
    model_name: str

    async def propose(self, request: KycRequest) -> KycProposal: ...


@dataclass(frozen=True)
class _AdapterProvider:
    factory: Callable[..., Any]
    live_factory: Callable[..., Any]
    errors: tuple[tuple[type[Exception], tuple[type[Exception], ...]], ...]


_provider: _AdapterProvider | None = None
_PUBLIC_ERRORS = (ModelOutputInvalid, ModelUnavailable, PrivateDocumentsUnavailable)


def configure_adapter_provider(
    *,
    factory: Callable[..., Any],
    live_factory: Callable[..., Any],
    model_output_invalid: tuple[type[Exception], ...],
    model_unavailable: tuple[type[Exception], ...],
    private_documents_unavailable: tuple[type[Exception], ...],
) -> None:
    """Install factories and explicit private exception families once.

    Supply empty tuples for families already using the public exception classes.
    Public classes keep stable identity. Translated errors preserve their args
    and cause; other exceptions, including cancellation, propagate unchanged.
    """
    global _provider
    if not callable(factory) or not callable(live_factory):
        raise TypeError("Adapter provider factories must be callable")
    families = (model_output_invalid, model_unavailable, private_documents_unavailable)
    for family in families:
        if not isinstance(family, tuple) or any(
            not isinstance(error, type) or not issubclass(error, Exception)
            for error in family
        ):
            raise TypeError("Adapter error families must be tuples of exception types")
    for index, family in enumerate(families):
        for other in families[index + 1:]:
            if any(issubclass(left, right) or issubclass(right, left)
                   for left in family for right in other):
                raise TypeError("Adapter error families must not overlap")
    if _provider is not None:
        raise PrivateImplementationUnavailable("Adapter provider is already configured")
    _provider = _AdapterProvider(factory, live_factory, tuple(zip(_PUBLIC_ERRORS, families)))


def _require_provider() -> _AdapterProvider:
    if _provider is None:
        raise PrivateImplementationUnavailable(
            "Private adapter provider is required; call configure_adapter_provider "
            "before importing agent.app"
        )
    return _provider


def _mapped_error(error: Exception, provider: _AdapterProvider) -> Exception | None:
    if isinstance(error, _PUBLIC_ERRORS):
        return None
    matches = [public_error for public_error, private_errors in provider.errors
               if isinstance(error, private_errors)]
    if len(matches) > 1:
        raise PrivateImplementationUnavailable(
            "Private adapter exception matches multiple public error families"
        ) from error
    return matches[0](*error.args) if matches else None


def _invoke(provider: _AdapterProvider, operation: Callable[..., Any],
            *args: Any, **kwargs: Any) -> Any:
    try:
        return operation(*args, **kwargs)
    except Exception as error:
        mapped = _mapped_error(error, provider)
        if mapped is not None:
            raise mapped from error
        raise


class _AdapterConnection:
    def __init__(self, adapter: Any, provider: _AdapterProvider) -> None:
        self._adapter = adapter
        self._provider = provider

    @property
    def model_name(self) -> str:
        return _invoke(self._provider, getattr, self._adapter, "model_name")

    async def _invoke_async(self, operation: Callable[..., Any],
                            *args: Any, **kwargs: Any) -> Any:
        try:
            return await operation(*args, **kwargs)
        except Exception as error:
            mapped = _mapped_error(error, self._provider)
            if mapped is not None:
                raise mapped from error
            raise

    async def propose(self, *args: Any, **kwargs: Any) -> Any:
        operation = _invoke(self._provider, getattr, self._adapter, "propose")
        return await self._invoke_async(operation, *args, **kwargs)

    @property
    def capture(self) -> Any:
        try:
            operation = getattr(self._adapter, "capture")
        except AttributeError:
            raise
        except Exception as error:
            mapped = _mapped_error(error, self._provider)
            if mapped is not None:
                raise mapped from error
            raise
        if not callable(operation):
            return operation

        async def capture(*args: Any, **kwargs: Any) -> Any:
            return await self._invoke_async(operation, *args, **kwargs)

        return capture


def _connect(provider: _AdapterProvider, factory: Callable[..., Any],
             *args: Any, **kwargs: Any) -> Adapter:
    return _AdapterConnection(_invoke(provider, factory, *args, **kwargs), provider)


def make_adapter(*args: Any, **kwargs: Any) -> Adapter:
    """Delegate selection to the required private factory without a fallback."""
    provider = _require_provider()
    return _connect(provider, provider.factory, *args, **kwargs)


@dataclass(frozen=True)
class HttpAdapterBindings:
    propose: Callable[..., Any] | None
    capture: Callable[..., Any] | None
    model_name: str | None


def bind_http_adapter(adapter: Any) -> HttpAdapterBindings:
    """Resolve HTTP dependencies once at startup, without calling operations.

    Descriptor resolution may execute provider code during startup. Failed or
    synchronous operations are unavailable; no callable is probed by invoking it.
    """
    connection = adapter if type(adapter) is _AdapterConnection else None
    target = connection._adapter if connection is not None else adapter

    def bind(name):
        try:
            operation = getattr(target, name, None)
            asynchronous = inspect.iscoroutinefunction(operation) or (
                callable(operation) and inspect.iscoroutinefunction(getattr(type(operation), "__call__", None))
            )
        except Exception:
            return None
        if not asynchronous:
            return None
        if connection is None:
            return operation

        async def invoke(*args, **kwargs):
            return await connection._invoke_async(operation, *args, **kwargs)

        return invoke

    try:
        model_name = getattr(target, "model_name", None)
    except Exception:
        model_name = None
    if type(model_name) is not str:
        model_name = None
    return HttpAdapterBindings(bind("propose"), bind("capture"), model_name)


class LiveAdapter:
    """Retain the explicit live-constructor entry point without live behavior."""

    def __new__(cls, *args: Any, **kwargs: Any) -> Adapter:
        provider = _require_provider()
        return _connect(provider, provider.live_factory, *args, **kwargs)
