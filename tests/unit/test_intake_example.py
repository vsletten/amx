from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from amx.examples import intake
from amx.profile import Intent, Lane, build, parse
from amx.runtime import Context, Refuse


@pytest.mark.parametrize(
    ("subject", "state"),
    [("AMX scenario t_x", "completed"), ("AMX scenario t_x [keep-open]", "working")],
)
def test_intake_closes_a_request_unless_asked_to_keep_it_open(
    tmp_path, monkeypatch, subject: str, state: str
) -> None:
    monkeypatch.setenv("AMX_HANDLER_LOG", str(tmp_path / "handler.jsonl"))
    request = build(
        sender="scheduler+t_x@agents.northwind.test",
        to="intake+t_x@agents.contoso.test",
        subject=subject,
        intent="request",
        task="t_x",
        task_state="submitted",
        text="Please process scenario t_x.",
        message_id="<s10@agents.northwind.test>",
    )
    replies: list[dict[str, Any]] = []
    context = Context(agent="intake", metadata={}, reply_message=lambda **m: replies.append(m))

    intake.handle(parse(request.as_bytes()), context)

    assert [reply["task_state"] for reply in replies] == [state]


@pytest.mark.parametrize(
    ("callback", "intent", "lane", "subject", "state"),
    [
        (False, "request", "agent", "[keep-open]", None),
        (True, "error", "agent", "[loop] [keep-open]", None),
        (True, "request", "human", "[reply] [loop] [keep-open]", None),
        (True, "request", "human", "[keep-open]", None),
        (True, "request", "system", "[loop] [keep-open]", None),
        (True, "request", "agent", "[loop] [keep-open]", "working"),
        (True, "update", "agent", "[loop] [keep-open]", "working"),
        (True, "request", "agent", "[KEEP-OPEN]", "working"),
        (True, "request", "agent", "ordinary request", "completed"),
        (True, "response", "agent", "[keep-open]", None),
    ],
)
def test_intake_reply_precedence(
    tmp_path,
    monkeypatch,
    callback: bool,
    intent: Intent,
    lane: Lane,
    subject: str,
    state: str | None,
) -> None:
    monkeypatch.setenv("AMX_HANDLER_LOG", str(tmp_path / "handler.jsonl"))
    message = build(
        sender="scheduler+t_x@agents.northwind.test",
        to="intake+t_x@agents.contoso.test",
        subject=subject,
        intent=intent,
        in_reply_to="<original@agents.northwind.test>" if intent == "response" else None,
        task="t_x",
        task_state="submitted",
        text="Request",
    )
    inbound = replace(parse(message.as_bytes()), lane=lane)
    replies: list[dict[str, Any]] = []
    context = Context(
        agent="intake",
        metadata={},
        reply_message=(lambda **reply: replies.append(reply)) if callback else None,
    )

    intake.handle(inbound, context)

    human_reply = callback and intent != "error" and lane == "human" and "[reply]" in subject
    assert len(replies) == int(human_reply or state is not None)
    if replies:
        assert replies[0].get("task_state") == state
        assert replies[0]["intent"] == "response"
    if "[loop]" in subject and state == "working":
        assert replies[0]["text"] == "Loop reply from intake."


@pytest.mark.parametrize("lane", ["agent", "human"])
def test_intake_refuses_a_marked_message_on_either_lane_and_never_a_bounce(
    tmp_path, monkeypatch, lane: Lane
) -> None:
    monkeypatch.setenv("AMX_HANDLER_LOG", str(tmp_path / "handler.jsonl"))
    message = build(
        sender="scheduler+t_x@agents.northwind.test",
        to="intake+t_x@agents.contoso.test",
        subject="AMX scenario t_x [refuse]",
        intent="request",
        task="t_x",
        task_state="submitted",
        text="Request",
    )
    replies: list[dict[str, Any]] = []
    context = Context(agent="intake", metadata={}, reply_message=lambda **m: replies.append(m))
    with pytest.raises(Refuse) as refused:
        intake.handle(replace(parse(message.as_bytes()), lane=lane), context)
    assert (refused.value.code, refused.value.reason) == ("5.7.1", "policy")
    assert replies == []
    receive_only = Context(agent="intake-off", metadata={})
    with pytest.raises(Refuse):  # S18k's in-process comparison runs on intake-off
        intake.handle(replace(parse(message.as_bytes()), lane=lane), receive_only)
    bounce = replace(parse(message.as_bytes()), intent="error")
    intake.handle(bounce, context)  # a DSN carrying the marker is never refused
