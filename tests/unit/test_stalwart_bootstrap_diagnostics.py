"""Pinned CLI apply NDJSON is untrusted; publish only source vocabulary."""

import json

import pytest

from amx.adapters import stalwart

PLAN = [{"@type": "upsert", "object": "Certificate", "value": {}}]


def record(**changes):
    return {
        "op": "upsert",
        "object": "Certificate",
        "index": 0,
        "status": "error",
        "error": (
            "Certificate: update failed for id PRIVATE: error: invalidProperties | "
            "PRIVATE | Properties: /privateKey/PRIVATE/filePath"
        ),
    } | changes


def test_apply_failure_identifies_operation_without_secrets():
    output = json.dumps(record()) + '\n{"op":"summary","PRIVATE":"PRIVATE"}\n'
    assert stalwart.bootstrap_failure_diagnostic(output, PLAN) == (
        "operation=upsert object=Certificate index=0 status=error "
        "code=invalidProperties property=filePath"
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"op": "PRIVATE"},
        {"object": "PRIVATE"},
        {"object": "Account"},
        {"index": -1},
        {"index": 1},
        {"index": True},
        {"index": "0"},
        {"status": "PRIVATE"},
        {"status": "ok"},
    ],
)
def test_untrusted_or_mismatched_reporter_fields_are_ignored(changes):
    assert stalwart.bootstrap_failure_diagnostic(json.dumps(record(**changes)), PLAN) is None


@pytest.mark.parametrize("output", [None, b"PRIVATE", "PRIVATE", "[]", "{}", "null"])
def test_non_reporter_output_is_ignored(output):
    assert stalwart.bootstrap_failure_diagnostic(output, PLAN) is None


def test_unknown_error_and_property_are_never_forwarded():
    output = json.dumps(record(error="error: PRIVATE | Properties: /PRIVATE"))
    assert stalwart.bootstrap_failure_diagnostic(output, PLAN) == (
        "operation=upsert object=Certificate index=0 status=error code=unknown property=unknown"
    )


def test_diagnostic_parser_is_bounded():
    assert stalwart.bootstrap_failure_diagnostic("x" * 65536 + json.dumps(record()), PLAN) is None
    assert (
        stalwart.bootstrap_failure_diagnostic(json.dumps(record(error="x" * 16384)), PLAN) is None
    )


def test_plan_cannot_introduce_new_diagnostic_vocabulary():
    plan = [{"@type": "PRIVATE", "object": "PRIVATE"}]
    output = json.dumps(record(op="PRIVATE", object="PRIVATE"))
    assert stalwart.bootstrap_failure_diagnostic(output, plan) is None
