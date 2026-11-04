"""Stored JSON input boundary regressions; synthetic mocked IO only, NOT_RUN."""
import os
from pathlib import Path
import stat
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from evaluation import export_provider

LIMIT = 8 * 1024 * 1024


class FakeOS:
    O_RDONLY = os.O_RDONLY
    O_NONBLOCK = os.O_NONBLOCK

    def __init__(self, payload=b'{}', mode=stat.S_IFREG | 0o600, size=None):
        self.payload = payload
        self.offset = 0
        self.open = Mock(return_value=73)
        self.fstat = Mock(return_value=SimpleNamespace(st_mode=mode,
            st_size=len(payload) if size is None else size))
        self.read = Mock(side_effect=self.reading)
        self.close = Mock()

    def reading(self, fd, count):
        assert fd == 73
        assert 0 < count <= 65536
        chunk = self.payload[self.offset:self.offset + count]
        self.offset += len(chunk)
        return chunk


def install(monkeypatch, **kwargs):
    fake = FakeOS(**kwargs)
    monkeypatch.setattr(export_provider, 'os', fake)
    return fake


@pytest.mark.parametrize('kind', [stat.S_IFIFO, stat.S_IFCHR, stat.S_IFBLK,
                                 stat.S_IFDIR, stat.S_IFSOCK])
def test_nonregular_inputs_are_rejected_before_any_read(monkeypatch, kind):
    fake = install(monkeypatch, mode=kind | 0o600)
    with pytest.raises(ValueError, match='^input must be a regular file$'):
        export_provider._strict_json('synthetic-report.json')
    fake.open.assert_called_once_with(Path('synthetic-report.json'), fake.O_RDONLY | fake.O_NONBLOCK)
    fake.fstat.assert_called_once_with(73)
    fake.read.assert_not_called()
    fake.close.assert_called_once_with(73)


def test_regular_unicode_json_keeps_existing_values_and_nonblocking_follow_semantics(monkeypatch):
    fake = install(monkeypatch, payload='{"label":"합성","value":1.5}'.encode('utf-8'))
    assert export_provider._strict_json('synthetic-link-to-report.json') == {'label': '합성', 'value': 1.5}
    # No O_NOFOLLOW is added: an existing symlink-to-regular input remains valid.
    fake.open.assert_called_once_with(Path('synthetic-link-to-report.json'), os.O_RDONLY | os.O_NONBLOCK)
    fake.close.assert_called_once_with(73)
    assert fake.offset == len(fake.payload)


def test_declared_oversize_file_is_rejected_without_read(monkeypatch):
    fake = install(monkeypatch, size=LIMIT + 1)
    with pytest.raises(ValueError, match='^input is too large$'):
        export_provider._strict_json('synthetic-report.json')
    fake.read.assert_not_called()
    fake.close.assert_called_once_with(73)


def test_exact_byte_limit_is_accepted_with_bounded_eof_check(monkeypatch):
    fake = install(monkeypatch, payload=b'{}' + b' ' * (LIMIT - 2))
    assert export_provider._strict_json('synthetic-report.json') == {}
    assert fake.offset == LIMIT
    assert fake.read.call_args_list[-1].args == (73, 1)
    fake.close.assert_called_once_with(73)


def test_growth_after_stat_stops_at_limit_plus_one_without_parsing(monkeypatch):
    fake = install(monkeypatch, payload=b'x' * (LIMIT + 100), size=0)
    with pytest.raises(ValueError, match='^input is too large$'):
        export_provider._strict_json('synthetic-report.json')
    assert fake.offset == LIMIT + 1
    assert sum(call.args[1] for call in fake.read.call_args_list) == LIMIT + 1
    fake.close.assert_called_once_with(73)


@pytest.mark.parametrize('payload', [b'{', b'{"x":1,"x":2}', b'{"x":NaN}', b'\xff'])
def test_existing_json_refusals_close_before_parser_failure(monkeypatch, payload):
    fake = install(monkeypatch, payload=payload)
    with pytest.raises((ValueError, UnicodeError)):
        export_provider._strict_json('synthetic-report.json')
    fake.close.assert_called_once_with(73)


@pytest.mark.parametrize('stage', ['fstat', 'read'])
def test_acquired_fd_is_closed_once_on_metadata_or_read_failure(monkeypatch, stage):
    fake = install(monkeypatch)
    getattr(fake, stage).side_effect = OSError('synthetic failure')
    with pytest.raises(OSError):
        export_provider._strict_json('synthetic-report.json')
    fake.close.assert_called_once_with(73)
    if stage == 'fstat':
        fake.read.assert_not_called()


def test_failed_open_does_not_close_an_unacquired_descriptor(monkeypatch):
    fake = install(monkeypatch)
    fake.open.side_effect = OSError('synthetic failure')
    with pytest.raises(OSError):
        export_provider._strict_json('synthetic-report.json')
    fake.close.assert_not_called()
    fake.read.assert_not_called()


def test_close_failure_prevents_returning_a_parsed_success(monkeypatch):
    fake = install(monkeypatch)
    fake.close.side_effect = OSError('synthetic close uncertainty')
    with pytest.raises(OSError):
        export_provider._strict_json('synthetic-report.json')
    fake.close.assert_called_once_with(73)


def test_platform_without_nonblocking_open_refuses_before_open(monkeypatch):
    fake = SimpleNamespace(open=Mock())
    monkeypatch.setattr(export_provider, 'os', fake)
    with pytest.raises(ValueError, match='^regular input files are unavailable$'):
        export_provider._strict_json('synthetic-report.json')
    fake.open.assert_not_called()
