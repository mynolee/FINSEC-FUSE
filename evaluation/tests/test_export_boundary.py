"""Explicit provider injection and non-sensitive CLI boundary contracts."""

import importlib
import sys
import traceback
import types
from pathlib import Path

import pytest


_CLI_FAILURE = "Exporter execution unavailable or failed.\n"


@pytest.fixture
def boundary(monkeypatch):
    module = importlib.import_module("evaluation.export")
    expected = Path(__file__).resolve().parents[1] / "export.py"
    assert Path(module.__file__).resolve() == expected, "Wrong exporter boundary module loaded"
    monkeypatch.setattr(module, "_provider", None)
    monkeypatch.setattr(module, "_cli", None)
    return module


@pytest.fixture
def provider():
    return types.ModuleType("synthetic_export_provider")


def test_environment_cannot_select_or_import_a_provider(monkeypatch, boundary, capsys):
    monkeypatch.setenv("FUSE_PRIVATE_EXPORT_MODULE", "untrusted_export_provider")
    imports = []

    def forbidden_import(name, *args, **kwargs):
        imports.append(name)
        raise AssertionError("No provider module may be imported")

    monkeypatch.setattr(importlib, "import_module", forbidden_import)
    with pytest.raises(RuntimeError, match="explicitly configured"):
        getattr(boundary, "export_evidence_bundle")
    assert boundary.run_export_cli([]) == 1
    assert imports == []
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == _CLI_FAILURE


def test_same_boundary_object_is_rejected_through_an_alias(monkeypatch, boundary):
    monkeypatch.setitem(sys.modules, "synthetic_boundary_alias", boundary)
    alias = sys.modules["synthetic_boundary_alias"]
    monkeypatch.setattr(boundary, "__name__", "synthetic_boundary_alias")
    assert alias is boundary
    with pytest.raises(ValueError, match="independent"):
        boundary.configure_export_provider(alias)


def test_independent_provider_with_same_name_is_not_confused_with_boundary(boundary):
    provider = types.ModuleType(boundary.__name__)
    provider.sanitize_trace = lambda value: value
    boundary.configure_export_provider(provider)
    assert boundary.sanitize_trace is provider.sanitize_trace


def test_boundary_cli_callable_cannot_be_injected_as_itself(boundary, provider):
    callback_alias = boundary.run_export_cli
    with pytest.raises(ValueError, match="own CLI"):
        boundary.configure_export_provider(provider, cli=callback_alias)


def test_configuration_requires_an_object_and_a_callable(boundary, provider):
    with pytest.raises(ValueError):
        boundary.configure_export_provider(None)
    with pytest.raises(TypeError):
        boundary.configure_export_provider(provider, cli=object())
    with pytest.raises(RuntimeError, match="explicitly configured"):
        getattr(boundary, "export_evidence_bundle")


@pytest.mark.parametrize(
    "name", ["export_evidence_bundle", "sanitize_trace", "calculate_split_metrics", "_expected_match"]
)
def test_named_contracts_are_original_provider_objects(boundary, provider, name):
    def implementation(*args, **kwargs):
        return args, kwargs

    setattr(provider, name, implementation)
    boundary.configure_export_provider(provider)
    assert getattr(boundary, name) is implementation


def test_results_inputs_calls_and_manifest_remain_provider_owned(boundary, provider, tmp_path):
    report, manifest = object(), object()
    saved = tmp_path / "manifest.json"
    original = b'{"public-contract":"existing"}'
    saved.write_bytes(original)
    calls = []

    def implementation(actual_report, actual_manifest, output, *, marker):
        calls.append((actual_report, actual_manifest, output, marker))
        return output

    provider.export_evidence_bundle = implementation
    boundary.configure_export_provider(provider)
    marker = object()
    assert boundary.export_evidence_bundle(report, manifest, tmp_path, marker=marker) is tmp_path
    assert boundary.export_evidence_bundle(report, manifest, tmp_path, marker=marker) is tmp_path
    assert calls == [(report, manifest, tmp_path, marker), (report, manifest, tmp_path, marker)]
    assert saved.read_bytes() == original


def test_provider_api_exception_is_not_rewritten(boundary, provider):
    failure = ValueError("synthetic provider rejection")

    def implementation(*args, **kwargs):
        raise failure

    provider.export_evidence_bundle = implementation
    boundary.configure_export_provider(provider)
    with pytest.raises(ValueError) as caught:
        boundary.export_evidence_bundle(object(), object(), object())
    assert caught.value is failure


def test_provider_attribute_error_is_not_rewritten(boundary, provider):
    failure = AttributeError("synthetic provider attribute unavailable")

    def missing(name):
        raise failure

    provider.__getattr__ = missing
    boundary.configure_export_provider(provider)
    with pytest.raises(AttributeError) as caught:
        getattr(boundary, "missing_export_api")
    assert caught.value is failure


def test_provider_and_cli_identity_cannot_change(boundary, provider):
    callback = lambda argv: 0
    boundary.configure_export_provider(provider, cli=callback)
    boundary.configure_export_provider(provider, cli=callback)
    with pytest.raises(RuntimeError, match="must not change"):
        boundary.configure_export_provider(types.ModuleType("another_provider"), cli=callback)
    with pytest.raises(RuntimeError, match="must not change"):
        boundary.configure_export_provider(provider, cli=lambda argv: 0)


def test_export_list_follows_provider(boundary, provider):
    provider.public_symbol = object()
    provider._private_symbol = object()
    boundary.configure_export_provider(provider)
    assert boundary.__all__ == ["public_symbol"]
    declared = ["public_symbol"]
    provider.__all__ = declared
    assert boundary.__all__ is declared


def test_cli_requires_an_explicit_callable(boundary, provider, capsys):
    boundary.configure_export_provider(provider)
    assert boundary.run_export_cli([]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == _CLI_FAILURE


@pytest.mark.parametrize("status", [None, 0])
def test_cli_passes_argument_tail_and_suppresses_provider_output(monkeypatch, boundary, provider, capsys, status):
    arguments = ["--report", "synthetic-report.json", "--provider-owned-option", "value"]
    monkeypatch.setattr(sys, "argv", ["public-export", *arguments])
    observed = []

    def callback(argv):
        observed.append(argv)
        print("SYNTHETIC_PROVIDER_OUTPUT")
        print("SYNTHETIC_PROVIDER_DIAGNOSTIC", file=sys.stderr)
        return status

    boundary.configure_export_provider(provider, cli=callback)
    assert boundary.run_export_cli() == 0
    assert observed == [arguments]
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


@pytest.mark.parametrize(
    "failure", [ValueError("SYNTHETIC_DETAIL"), SystemExit("SYNTHETIC_DETAIL"), SystemExit(7), KeyboardInterrupt("SYNTHETIC_DETAIL")]
)
def test_cli_failures_never_emit_exception_details_or_tracebacks(boundary, provider, capsys, failure):
    def callback(argv):
        print("SYNTHETIC_PROVIDER_OUTPUT")
        print("SYNTHETIC_PROVIDER_DIAGNOSTIC", file=sys.stderr)
        try:
            raise failure
        except BaseException:
            traceback.print_exc()
            raise

    boundary.configure_export_provider(provider, cli=callback)
    assert boundary.run_export_cli(["--provider-owned-option"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == _CLI_FAILURE


@pytest.mark.parametrize("via_system_exit", [False, True], ids=["return-2", "SystemExit-2"])
def test_cli_validation_status_is_preserved_with_fixed_error(boundary, provider, capsys, via_system_exit):
    def callback(argv):
        print("SYNTHETIC_PROVIDER_OUTPUT")
        print("SYNTHETIC_PROVIDER_DIAGNOSTIC", file=sys.stderr)
        if via_system_exit:
            raise SystemExit(2)
        return 2

    boundary.configure_export_provider(provider, cli=callback)
    assert boundary.run_export_cli([]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == _CLI_FAILURE


@pytest.mark.parametrize("status", [1, 17, -1, False, 2.0, "SYNTHETIC_DETAIL", object()])
def test_cli_non_success_results_use_fixed_failure(boundary, provider, capsys, status):
    boundary.configure_export_provider(provider, cli=lambda argv: status)
    assert boundary.run_export_cli([]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == _CLI_FAILURE


@pytest.mark.parametrize("status", [None, 0])
def test_cli_success_system_exit_has_no_output(boundary, provider, capsys, status):
    def callback(argv):
        raise SystemExit(status)

    boundary.configure_export_provider(provider, cli=callback)
    assert boundary.run_export_cli([]) == 0
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_failure_reporting_does_not_raise_a_second_exception(monkeypatch, boundary):
    class Unwritable:
        def write(self, text):
            raise OSError("SYNTHETIC_DIAGNOSTIC")

    monkeypatch.setattr(sys, "stderr", Unwritable())
    assert boundary.run_export_cli([]) == 1


def test_public_cli_configuration_failure_survives_an_unwritable_error_sink(monkeypatch):
    from evaluation import export_cli

    calls = []

    def unavailable():
        raise RuntimeError("SYNTHETIC_CONFIGURATION_DETAIL")

    class Unwritable:
        def write(self, text):
            calls.append(text)
            raise OSError("SYNTHETIC_SINK_DETAIL")

    monkeypatch.setattr(export_cli, "configure_public_exporter", unavailable)
    monkeypatch.setattr(sys, "stderr", Unwritable())
    assert export_cli.main([]) == 1
    assert calls == ["Exporter configuration unavailable.\n"]
