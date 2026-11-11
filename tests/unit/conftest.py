"""Unit fixtures must never share native agent custody state between tests."""

import pytest


@pytest.fixture(autouse=True)
def private_custody_state(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))


@pytest.fixture
def per_agent_dkim(monkeypatch: pytest.MonkeyPatch) -> None:
    """A lane from before SH-44: install makes no domain key, so each agent signs with its own.

    Such lanes keep working until `amx live install` stages their domain key; these tests pin
    that per-agent behavior (rotation, per-agent records) while it is still supported.
    """
    from amx import domain_dkim

    monkeypatch.setattr(
        domain_dkim, "ensure", lambda site, **_kw: domain_dkim.DomainDkim(active="amx.2000-01")
    )
