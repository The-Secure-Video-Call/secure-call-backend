import pytest

from signaling import consumers
from signaling.rate_limits import new_join_limiter, new_turn_credential_limiter


@pytest.fixture(autouse=True)
def fresh_rate_limiters(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test starts with empty counters; they would otherwise add up across tests."""
    monkeypatch.setattr(consumers, "join_limiter", new_join_limiter())
    monkeypatch.setattr(consumers, "turn_credential_limiter", new_turn_credential_limiter())
