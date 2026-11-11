from __future__ import annotations

import json
from dataclasses import replace
from email import policy
from pathlib import Path

import pytest

from amx.examples import llm_agent
from amx.examples.llm_agent import Brief, parse_decision, reply_cc, tools
from amx.profile import build, parse
from amx.runtime import Context, TryLater
from amx.sdk import Sent

BRIEF = Brief(
    role="You book inspections.",
    slots={"tue-0900": "Tuesday 09:00", "thu-1000": "Thursday 10:00"},
    cc=("victor@northwind.test",),
    max_replies=2,
)


def _inbound(text: str = "Please book an inspection.", *, lane: str = "agent"):
    raw = build(
        sender="planner+t_a@agents.northwind.test",
        to="inspections+t_a@agents.contoso.test",
        cc="victor@northwind.test, Ops <ops@contoso.test>",
        subject="Site inspection",
        intent="request",
        task="t_a",
        task_state="submitted",
        text=text,
        message_id="<m1@agents.northwind.test>",
    ).as_bytes(policy=policy.SMTP)
    return replace(parse(raw), lane=lane)


def _response(name: str, arguments: dict[str, object] | str) -> dict[str, object]:
    encoded = arguments if isinstance(arguments, str) else json.dumps(arguments)
    call = {"function": {"name": name, "arguments": encoded}}
    return {"model": "test-model", "choices": [{"message": {"tool_calls": [call]}}]}


class FakeClient:
    model = "test-model"

    def __init__(self, response=None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error
        self.calls: list[list[dict[str, object]]] = []

    def complete(self, messages, tool_specs):
        self.calls.append(messages)
        if self.error is not None:
            raise self.error
        return self.response


@pytest.fixture
def briefs(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "briefs.yaml"
    path.write_text(
        "inspections:\n  role: You book inspections.\n  cc: [victor@northwind.test]\n"
        "  max_replies: 2\n  slots:\n    tue-0900: Tuesday 09:00\n    thu-1000: Thursday 10:00\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("AMX_LLM_BRIEFS", str(path))
    monkeypatch.setenv("AMX_LLM_STATE", str(tmp_path / "llm"))
    monkeypatch.setenv("AMX_HANDLER_LOG", str(tmp_path / "handler.jsonl"))
    return tmp_path


def _context(sent: list[dict[str, object]], held: str | None = None) -> Context:
    def reply(**message):
        sent.append(message)
        return Sent("t_a", f"<r{len(sent)}@agents.contoso.test>", held)

    return Context(
        agent="inspections",
        metadata={"recipient": "inspections+t_a@agents.contoso.test"},
        reply_message=reply,
    )


def _log(tmp_path: Path) -> list[dict[str, object]]:
    lines = (tmp_path / "handler.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def test_the_model_can_name_only_the_briefs_slots() -> None:
    reply = tools(BRIEF)[0]["function"]["parameters"]["properties"]
    assert reply["slots"]["items"]["enum"] == ["thu-1000", "tue-0900"]


def test_a_decision_keeps_only_slots_from_the_brief() -> None:
    decision = parse_decision(
        _response(
            "reply",
            {"decision": "book", "slots": ["thu-1000", "sat-0800"], "text": "Booked.", "done": 1},
        ),
        BRIEF,
    )
    assert (decision.tool, decision.decision, decision.slots, decision.done) == (
        "reply",
        "book",
        ("thu-1000",),
        True,
    )
    assert decision.rejected_slots == ("sat-0800",)


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        ({"choices": [{"message": {"content": "Sure!"}}]}, "without calling a tool"),
        (_response("reply", "{not json"), "not JSON"),
        (_response("no_reply", {"reason": "just thanks"}), "just thanks"),
    ],
)
def test_anything_but_a_well_formed_reply_sends_nothing(response, reason) -> None:
    decision = parse_decision(response, BRIEF)
    assert decision.tool == "no_reply"
    assert reason in (decision.reason or "")


def test_an_unknown_decision_becomes_ask() -> None:
    response = _response("reply", {"decision": "wire money", "slots": [], "text": "?"})
    assert parse_decision(response, BRIEF).decision == "ask"


PARTICIPANTS = {
    "planner@agents.northwind.test",
    "inspections@agents.contoso.test",
    "victor@northwind.test",
    "ops@contoso.test",
}


def test_reply_all_drops_this_agent_and_the_sender_and_adds_the_brief_cc() -> None:
    cc = reply_cc(_inbound(), "inspections@agents.contoso.test", BRIEF, PARTICIPANTS)
    assert cc == ["victor@northwind.test", "ops@contoso.test"]


def test_reply_all_never_copies_an_address_a_header_merely_names() -> None:
    raw = _inbound().raw.replace(
        b"Cc: victor@northwind.test",
        b"Cc: victor@northwind.test, billing@elsewhere.test, intake+t_other@agents.contoso.test",
    )
    inbound = replace(parse(raw), lane="human")
    participants = {*PARTICIPANTS, "intake@agents.contoso.test"}
    cc = reply_cc(inbound, "inspections@agents.contoso.test", BRIEF, participants)
    # billing@ was never on a verified agent's message; intake loses the planted task token.
    assert cc == ["victor@northwind.test", "intake@agents.contoso.test", "ops@contoso.test"]


def test_handle_replies_through_ctx_with_a_checked_machine_part(briefs) -> None:
    sent: list[dict[str, object]] = []
    client = FakeClient(
        _response(
            "reply",
            {
                "decision": "propose",
                "slots": ["tue-0900", "thu-1000"],
                "text": "Tue or Thu?",
                "done": False,
            },
        )
    )
    llm_agent.handle(_inbound(), _context(sent), client=client)
    assert len(sent) == 1
    message = sent[0]
    assert message["intent"] == "response" and message["task_state"] == "working"
    assert message["schema"] == llm_agent.RESPONSE_SCHEMA
    assert message["payload"] == {
        "result": {
            "decision": "propose",
            "slots": [
                {"id": "tue-0900", "time": "Tuesday 09:00"},
                {"id": "thu-1000", "time": "Thursday 10:00"},
            ],
            "done": False,
        }
    }
    assert message["cc"] == ["victor@northwind.test", "ops@contoso.test"]
    prompt = client.calls[0]
    # The brief is the system prompt; the mail only ever arrives as data in the user turn.
    assert "You book inspections." in prompt[0]["content"]
    assert "- tue-0900: Tuesday 09:00" in prompt[0]["content"]
    assert "Please book an inspection." not in prompt[0]["content"]
    assert json.loads(prompt[1]["content"])["new_message"]["text"] == "Please book an inspection."
    (record,) = _log(briefs)
    assert record["tool"] == "reply" and record["sent"] == "<r1@agents.contoso.test>"
    memory = json.loads((briefs / "llm" / "inspections" / "t_a.json").read_text("utf-8"))
    assert [entry["from"] for entry in memory["thread"]] == [
        "planner+t_a@agents.northwind.test",
        "you",
    ]
    # The verified agent's message named the participants the next reply may copy.
    assert set(memory["participants"]) == {
        "planner@agents.northwind.test",
        "inspections@agents.contoso.test",
        "victor@northwind.test",
        "ops@contoso.test",
    }


def test_memory_written_before_participants_were_tracked_still_loads(tmp_path) -> None:
    memory = llm_agent.Memory(tmp_path, "inspections", "t_a")
    memory.path.parent.mkdir(parents=True)
    memory.path.write_text(json.dumps([{"from": "you", "text": "Hi"}]), encoding="utf-8")
    assert memory.load() == ([{"from": "you", "text": "Hi"}], set())


def test_a_persons_message_adds_no_participants(briefs) -> None:
    sent: list[dict[str, object]] = []
    client = FakeClient(
        _response("reply", {"decision": "ask", "slots": [], "text": "Which day?", "done": False})
    )
    llm_agent.handle(_inbound(lane="human"), _context(sent), client=client)
    assert sent[0]["cc"] == ["victor@northwind.test"]  # only the brief's cc
    memory = json.loads((briefs / "llm" / "inspections" / "t_a.json").read_text("utf-8"))
    assert memory["participants"] == []


def test_handle_records_a_hold_the_gateway_applied(briefs) -> None:
    sent: list[dict[str, object]] = []
    client = FakeClient(
        _response("reply", {"decision": "book", "slots": ["thu-1000"], "text": "OK", "done": True})
    )
    llm_agent.handle(_inbound(), _context(sent, held="tainted-input"), client=client)
    assert _log(briefs)[-1]["held"] == "tainted-input"


def test_handle_stops_replying_when_the_budget_is_spent(briefs) -> None:
    sent: list[dict[str, object]] = []
    client = FakeClient(
        _response("reply", {"decision": "ask", "slots": [], "text": "Hmm?", "done": False})
    )
    for _ in range(3):
        llm_agent.handle(_inbound(), _context(sent), client=client)
    assert len(sent) == 2 and len(client.calls) == 2
    assert "budget" in str(_log(briefs)[-1]["reason"])


def test_bounces_and_local_events_never_reach_the_model(briefs) -> None:
    client = FakeClient()
    llm_agent.handle(_inbound(lane="system"), _context([]), client=client)
    assert client.calls == []


def test_an_unreachable_model_is_retried_later(briefs) -> None:
    client = FakeClient(error=OSError("connection refused"))
    with pytest.raises(TryLater):
        llm_agent.handle(_inbound(), _context([]), client=client)
    (record,) = _log(briefs)
    assert record["tool"] == "retry" and "connection refused" in record["reason"]
    assert not (briefs / "llm" / "inspections" / "t_a.json").exists()  # retried from scratch


def test_the_model_timeout_is_configurable(monkeypatch) -> None:
    monkeypatch.setenv("AMX_LLM_TIMEOUT", "12.5")
    assert llm_agent.ChatClient.from_env().timeout == 12.5
    monkeypatch.delenv("AMX_LLM_TIMEOUT")
    assert llm_agent.ChatClient.from_env().timeout == llm_agent.DEFAULT_TIMEOUT


def test_a_task_token_that_is_a_path_never_becomes_a_file(briefs) -> None:
    client = FakeClient()
    message = replace(_inbound(), task="/data/llm/planner/t_victim")
    llm_agent.handle(message, _context([]), client=client)
    assert client.calls == []
    assert _log(briefs)[-1]["reason"] == "invalid task token"
    with pytest.raises(ValueError):
        llm_agent.Memory(briefs, "inspections", "../t_victim")
