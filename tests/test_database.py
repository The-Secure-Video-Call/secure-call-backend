"""Real database connection. Runs only when PostgreSQL is configured: CI starts one for
every run; locally, set the POSTGRES_* variables (see README.md)."""

import os

import pytest
from django.db import connection

pytestmark = [
    pytest.mark.skipif(
        not os.environ.get("POSTGRES_HOST"), reason="no PostgreSQL configured (POSTGRES_HOST)"
    ),
    pytest.mark.django_db,
]


def test_connects_to_postgresql() -> None:
    assert connection.vendor == "postgresql"


def test_can_run_a_query() -> None:
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
        assert cursor.fetchone() == (1,)
