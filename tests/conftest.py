"""Explicit test-environment configuration for API integration tests."""

from __future__ import annotations

import os

import pytest

# API tests intentionally use the narrowly scoped test principal.  Production,
# staging, and development never inherit this bypass from pytest detection.
os.environ["ENVIRONMENT"] = "test"
os.environ["AUTH_TEST_BYPASS_ENABLED"] = "true"


@pytest.fixture(autouse=True)
def clear_cached_settings():
    """Keep settings tests isolated when they temporarily change env vars."""

    from vulnops.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
