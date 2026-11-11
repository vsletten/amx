from __future__ import annotations

import json
from email import policy
from email.parser import BytesParser
from pathlib import Path

import pytest

from amx.profile import ProfileError, parse

CORPUS = Path(__file__).parents[2] / "spec" / "corpus"


def _pairs() -> list[tuple[Path, Path]]:
    messages = sorted(CORPUS.glob("*.eml"))
    expected = sorted(CORPUS.glob("*.expected.json"))
    assert 15 <= len(messages) <= 20
    assert {path.stem for path in messages} == {
        path.name.removesuffix(".expected.json") for path in expected
    }
    return [(message, message.with_suffix(".expected.json")) for message in messages]


@pytest.mark.parametrize(("message_path", "expected_path"), _pairs())
def test_corpus_message_matches_expected(message_path: Path, expected_path: Path) -> None:
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    raw = message_path.read_bytes()

    if "error" in expected:
        error = expected["error"]
        with pytest.raises(ProfileError) as caught:
            parse(raw)
        assert type(caught.value).__name__ == error["type"]
        assert error["contains"] in str(caught.value)
    else:
        assert parse(raw).as_dict() == expected["result"]


def test_corpus_covers_required_interoperability_and_failure_cases() -> None:
    names = {message.name for message, _expected in _pairs()}
    required_markers = {
        "proposal-example",
        "gmail",
        "delivered-to",
        "dsn-failed",
        "dsn-timeout",
        "mdn",
        "malformed",
        "invalid-schema",
        "no-text-plain",
        "references-101",
    }
    assert all(any(marker in name for name in names) for marker in required_markers)


def test_proposal_example_carries_its_documented_headers() -> None:
    raw = (CORPUS / "06-proposal-example-request.eml").read_bytes()
    message = BytesParser(policy=policy.default).parsebytes(raw)

    assert message["From"] == "scheduler+t_8f3a2c@agents.northwind.test"
    assert message["To"] == "intake@agents.contoso.test"
    assert message["Cc"] == "victor@northwind.test"
    assert message["Subject"] == "Request: site inspection, week of 2026-10-05"
    assert message["Message-ID"] == "<t_8f3a2c.1@agents.northwind.test>"
    assert message["Agent-Task"] == "t_8f3a2c"
    assert message["Agent-Card"] == "https://northwind.test/.well-known/agents/scheduler.json"
    assert message["Agent-Reply-By"] == "Wed, 23 Sep 2026 17:00:00 -0700"
