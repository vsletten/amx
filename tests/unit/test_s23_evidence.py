"""Offline regression for S23's per-submission policy-journal evidence."""

from pathlib import Path

import pytest

from amx.store import Store

OWNER_DETAIL = "[grant=owner trust=high can_open_tasks=true]"


@pytest.fixture
def evidence(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    from scenarios import test_s23_signed_in_owner as scenario

    return scenario, Store(tmp_path / "journal.sqlite")


def record(store, detail=OWNER_DETAIL, stage="eod"):
    store.record_policy(stage, "human-lane", "accept", None, None, detail)


def test_prior_case_cannot_satisfy_later_missing_owner_event(evidence):
    scenario, store = evidence
    assert scenario._policy_event_boundary(store) == 0
    record(store)
    scenario._assert_owner_grant_journaled(store, 0)
    boundary = scenario._policy_event_boundary(store)
    with pytest.raises(AssertionError, match="current submission's complete owner grant"):
        scenario._assert_owner_grant_journaled(store, boundary)
    record(store)
    scenario._assert_owner_grant_journaled(store, boundary)


@pytest.mark.parametrize(
    "detail",
    [
        "[grant=owner]",
        "[grant=owner can_open_tasks=true]",
        "[grant=owner trust=high]",
        "[grant=owner trust=low can_open_tasks=true]",
        "[grant=owner trust=high can_open_tasks=false]",
        "[grant=stranger trust=high can_open_tasks=true]",
        "[grant=owner trust=high can_open_tasks=trueish]",
    ],
)
def test_current_event_requires_complete_owner_detail(evidence, detail):
    scenario, store = evidence
    record(store)
    boundary = scenario._policy_event_boundary(store)
    record(store, detail)
    with pytest.raises(AssertionError, match="current submission's complete owner grant"):
        scenario._assert_owner_grant_journaled(store, boundary)


def test_owner_fields_cannot_be_combined_across_rows_or_stages(evidence):
    scenario, store = evidence
    record(store, "[grant=owner]")
    record(store, "[trust=high can_open_tasks=true]")
    record(store, stage="rcpt")
    with pytest.raises(AssertionError, match="current submission's complete owner grant"):
        scenario._assert_owner_grant_journaled(store, 0)


def test_current_owner_detail_can_follow_content_judgment(evidence):
    scenario, store = evidence
    record(store, "accepted [judge=observe; grant=owner trust=high can_open_tasks=true]")
    scenario._assert_owner_grant_journaled(store, 0)
