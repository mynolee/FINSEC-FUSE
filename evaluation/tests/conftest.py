"""Opt-in, per-test credentials; production code still requires explicit config."""
import secrets

import pytest


@pytest.fixture
def internal_service_token(monkeypatch):
    token = secrets.token_urlsafe(32)
    monkeypatch.setenv("FUSE_SERVICE_TOKEN", token)
    return token
