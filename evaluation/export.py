"""Exporter boundary with explicit in-process dependency injection only.

A trusted bootstrap must call configure_export_provider with an already-created
provider and, for CLI use, an explicit callable accepting the argument list.
No environment setting, module name, path, or automatic implementation is loaded.
Named APIs remain provider-owned. The CLI emits fixed failure output, preserves
validation status 2, and discards Python stdout/stderr writes.
This is not a sandbox for provider-created log handlers, native writes, or I/O.
"""

import contextlib as _contextlib
import sys as _sys
import threading as _threading
import types as _types


_BOUNDARY_MODULE = _sys.modules.get(__name__)
_provider = None
_cli = None
_configuration_lock = _threading.Lock()
_CLI_FAILURE = "Exporter execution unavailable or failed."
_CLI_FAILURE_STATUS = 1


class _DiscardOutput:
    def write(self, text):
        return len(text)

    def flush(self):
        return None


def configure_export_provider(provider, *, cli=None) -> None:
    """Bind an explicit provider and optional CLI callable to this module instance."""
    global _provider, _cli
    if provider is None or provider is _BOUNDARY_MODULE or (
        isinstance(provider, _types.ModuleType) and vars(provider) is globals()
    ):
        raise ValueError("An independent exporter provider object is required")
    if cli is not None and not callable(cli):
        raise TypeError("The exporter CLI implementation must be callable")
    if cli is run_export_cli:
        raise ValueError("The exporter boundary cannot be its own CLI implementation")
    with _configuration_lock:
        if _provider is not None and (provider is not _provider or cli is not _cli):
            raise RuntimeError("The exporter provider must not change after configuration")
        _provider, _cli = provider, cli


def _configuration():
    with _configuration_lock:
        if _provider is None:
            raise RuntimeError("An exporter provider must be explicitly configured")
        return _provider, _cli


def __getattr__(name: str):
    if name.startswith("__") and name != "__all__":
        raise AttributeError(name)
    provider, _ = _configuration()
    if name == "__all__":
        try:
            return provider.__all__
        except AttributeError:
            return [key for key in dir(provider) if not key.startswith("_")]
    return getattr(provider, name)


def _cli_status(value):
    if value is None:
        return 0
    if type(value) is int and value in (0, 2):
        return value
    return _CLI_FAILURE_STATUS


def run_export_cli(argv=None) -> int:
    """Call the injected CLI without emitting provider output or exception details.

    The callable receives argv[1:] (or the explicitly supplied argument list).
    None/zero and SystemExit(None/0) mean success. Integer 2 and SystemExit(2)
    preserve validation status 2. Other results or exceptions yield status 1.
    Both failure statuses emit the same non-sensitive error. Call only from a
    controlled CLI entry point; redirection does not isolate other threads or sinks.
    """
    status = _CLI_FAILURE_STATUS
    try:
        with _contextlib.redirect_stdout(_DiscardOutput()), _contextlib.redirect_stderr(_DiscardOutput()):
            _, cli = _configuration()
            if cli is None:
                raise RuntimeError("An exporter CLI callable must be explicitly configured")
            try:
                result = cli(list(_sys.argv[1:] if argv is None else argv))
            except SystemExit as stopped:
                status = _cli_status(stopped.code)
            else:
                status = _cli_status(result)
    except BaseException:
        # Never stringify, log, chain, or re-raise a provider exception here.
        status = _CLI_FAILURE_STATUS
    if status == 0:
        return 0
    try:
        _sys.stderr.write(_CLI_FAILURE + "\n")
    except BaseException:
        pass
    return status


if __name__ == "__main__":
    raise SystemExit(run_export_cli())
