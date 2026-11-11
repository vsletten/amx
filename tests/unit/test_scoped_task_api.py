"""Scoped task API validation and literal SQL/parameter-binding regressions."""

import sqlite3

import pytest

from amx.policy import STATE_API_VERSION, State
from amx.store import Store


@pytest.mark.parametrize("field", ["known_tasks", "closed_tasks"])
@pytest.mark.parametrize(
    "keys",
    [
        frozenset({"t_legacy"}),
        frozenset({("a",)}),
        frozenset({("a", 3)}),
        frozenset({("", "t_x")}),
        "t_x",
    ],
)
def test_state_rejects_legacy_or_malformed_task_keys(field, keys):
    assert STATE_API_VERSION == 2
    with pytest.raises(TypeError, match=rf"State\.{field} API v2.*\(agent, token\)"):
        State(agent_domain="agents.test", **{field: keys})


def test_closed_tasks_does_not_close_another_participant(tmp_path):
    store = Store(tmp_path / "store.sqlite")
    store.put_task("t_same", "alpha", "completed")
    store.put_task("t_same", "beta", "working")
    assert store.closed_tasks() == frozenset({("alpha", "t_same")})
    assert ("beta", "t_same") not in store.closed_tasks()
    state = State(
        agent_domain="agents.test", known_tasks=store.task_keys(), closed_tasks=store.closed_tasks()
    )
    assert ("beta", "t_same") in state.known_tasks
    assert ("beta", "t_same") not in state.closed_tasks


def test_sql_metacharacter_task_and_agent_values_are_bound(tmp_path, monkeypatch):
    calls = []
    connect = sqlite3.connect

    class Recording(sqlite3.Connection):
        def execute(self, sql, parameters=(), /):
            calls.append((sql, parameters))
            return super().execute(sql, parameters)

    monkeypatch.setattr(sqlite3, "connect", lambda *a, **kw: connect(*a, **kw, factory=Recording))
    store = Store(tmp_path / "store.sqlite")
    token = "t_x' OR 1=1; DROP TABLE tasks; --"
    agent = "agent' UNION SELECT 'wrong'; --"
    store.put_task("t_other", "other", "completed")
    store.put_task(token, agent, "working")
    assert store.task(token, agent)["state"] == "working"
    assert store.task(token)["agent"] == agent
    assert store.task("t_missing' OR 1=1 --", agent) is None
    assert store.put_task_unless_changed(token, agent, "completed", 0)
    assert not store.put_task_unless_changed(token, agent, "working", 1)
    assert not store.put_task(token, agent, "working")
    assert store.task_keys() == frozenset({(agent, token), ("other", "t_other")})
    assert store.task_keys(closed=True) == store.closed_tasks() == store.task_keys()
    bound = [(sql, params) for sql, params in calls if token in params or agent in params]
    assert bound
    assert all(token not in sql and agent not in sql for sql, _params in bound)
    assert any(
        "token = ? AND agent = ?" in sql and params == (token, agent) for sql, params in bound
    )
    assert any(
        "state IN (?, ?, ?)" in sql and params == ("canceled", "completed", "failed")
        for sql, params in calls
    )
