from __future__ import annotations

import ast
import copy
import importlib.util
import io
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from amx import judge


@pytest.fixture
def ab(monkeypatch):
    tools = Path(__file__).parents[2] / "tools"
    modules = []
    for name in ("jev_live_check", "jev_parts_agree_ab"):
        spec = importlib.util.spec_from_file_location(name, tools / f"{name}.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, name, module)
        spec.loader.exec_module(module)
        modules.append(module)
    return modules[-1]


def test_report_uses_unrounded_scores_at_the_refusal_boundary(ab):
    report = ab._report(
        [{"text": "agree", "parts": True}, {"text": "disagree", "parts": False}],
        {0: [0.1995, 0.1997], 1: [0.1996]},
    )
    assert report["agree"] == report["disagree"] == [0.2]
    assert report["agree_below_0.2"] == 1
    assert report["disagree_at_or_above_0.2"] == 0
    exact = ab._report(
        [{"text": "agree", "parts": True}, {"text": "disagree", "parts": False}],
        {0: [0.2], 1: [0.2]},
    )
    assert exact["agree_below_0.2"] == 0
    assert exact["disagree_at_or_above_0.2"] == 1


@pytest.mark.parametrize("value", [True, float("nan"), float("inf"), -0.1, 1.1, "0.9"])
def test_ab_score_rejects_answers_the_gateway_rejects(ab, monkeypatch, value):
    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    monkeypatch.setattr(
        judge._OPENER,
        "open",
        lambda *_args, **_kwargs: Response(
            json.dumps({"answers": {"parts_agree": {"noul": value}}}).encode()
        ),
    )
    body = ab._body(next(case for case in ab.live.CASES if "parts" in case), "shipped", "string")
    with pytest.raises(judge.JudgeUnavailable, match="malformed"):
        ab._score(body, "dummy-test-token")


def test_ab_score_preserves_custom_questions_and_protects_credentials(ab, monkeypatch):
    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    sent = []

    def open_request(request, timeout):
        sent.append((request, timeout))
        return Response(b'{"answers": {"parts_agree": {"noul": 0.1996}}}')

    monkeypatch.setattr(judge._OPENER, "open", open_request)
    case = next(case for case in ab.live.CASES if "payload" in case)
    body = ab._body(case, "m4b", "object")
    assert ab._score(body, "dummy-test-token") == 0.1996
    [(request, timeout)] = sent
    assert json.loads(request.data) == body
    assert timeout == 30
    assert request.full_url == "https://api.typesafe.ai/v1/systemone"
    assert request.unredirected_hdrs["Authorization"] == "Bearer dummy-test-token"
    assert "Authorization" not in request.headers


def test_ab_score_does_not_follow_a_cross_origin_redirect(ab, monkeypatch):
    received = []

    class Sink(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"answers": {"parts_agree": {"noul": 0.9}}}')

        def log_message(self, *_args):
            pass

    sink = HTTPServer(("127.0.0.1", 0), Sink)

    class Redirect(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{sink.server_port}/sink")
            self.end_headers()

        def log_message(self, *_args):
            pass

    source = HTTPServer(("127.0.0.1", 0), Redirect)
    client = judge.HttpJudge(base_url=f"http://127.0.0.1:{source.server_port}", timeout=2)
    monkeypatch.setattr(judge, "HttpJudge", lambda **_kwargs: client)
    for server in (sink, source):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        body = ab._body(ab.live.CASES[16], "shipped", "string")
        with pytest.raises(judge.JudgeUnavailable, match="HTTP 302"):
            ab._score(body, "dummy-test-token")
        assert received == []
    finally:
        source.shutdown()
        source.server_close()
        sink.shutdown()
        sink.server_close()


def test_m4b_baseline_is_independent_of_future_production_wording(ab, monkeypatch):
    original = copy.deepcopy(ab.M4B)
    monkeypatch.setitem(judge.PARTS_AGREE["instructions"], "question", "future question")
    monkeypatch.setitem(judge.PARTS_AGREE["criteria"]["true"], "examples", ["future example"])
    # Re-evaluate the baseline assignment as a fresh import would, without the separate
    # shipped-question consistency assertion masking historical-baseline drift.
    parsed = ast.parse(Path(ab.__file__).read_text())
    assignment = next(
        node
        for node in parsed.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "M4B" for target in node.targets)
    )
    namespace = {"amx_judge": judge}
    exec(compile(ast.Module(body=[assignment], type_ignores=[]), ab.__file__, "exec"), namespace)
    assert namespace["M4B"] == original


@pytest.mark.parametrize(
    "arguments",
    [
        ["--repeat", "0"],
        ["--repeat", "-1"],
        ["--variants", "shipped:strnig"],
        ["--variants", "missing:string"],
        ["--variants", "shipped"],
        ["--variants", ""],
    ],
)
def test_bad_experiment_arguments_fail_before_any_paid_call(ab, monkeypatch, arguments):
    monkeypatch.setattr(sys, "argv", ["jev_parts_agree_ab.py", *arguments])
    monkeypatch.setenv("TYPESAFE_API_KEY", "dummy-test-token")
    calls = []
    monkeypatch.setattr(ab, "_score", lambda *_args: calls.append(True))
    with pytest.raises(SystemExit) as raised:
        ab.main()
    assert raised.value.code == 2
    assert calls == []


def test_ab_shapes_keep_the_production_input_and_mark_content_as_lossy(ab):
    case = next(case for case in ab.live.CASES if "payload" in case)
    original = copy.deepcopy(case)
    string = ab._body(case, "shipped", "string")
    object_body = ab._body(case, "shipped", "object")
    content = ab._body(case, "shipped", "content")
    machine = json.loads(string["state"]["message"]["machine_part"])
    assert machine == case["payload"] == object_body["state"]["message"]["machine_part"]
    assert "id" not in content["state"]["message"]["machine_part"]["slots"][0]
    assert "done" not in content["state"]["message"]["machine_part"]
    assert case == original
    changed = ab._variant(ab.M4B, instructions__focus="changed")
    assert changed["instructions"]["focus"] == "changed"
    assert ab.M4B["instructions"]["focus"] != "changed"


@pytest.mark.parametrize("bookkeeping_matches", [True, False])
@pytest.mark.parametrize("values_match", [True, False])
@pytest.mark.parametrize("extra_action", [True, False])
def test_parts_agree_matrix_preserves_semantic_fields(
    bookkeeping_matches, values_match, extra_action
):
    """All eight matrix cells survive the real SDK writer and milter reader without loss."""
    from email import policy

    pytest.importorskip("Milter", reason="native reader requires the gateway extra")
    from amx.adapters.milter import judge_input
    from amx.profile import SCHEMA_BASE, build

    payload = {
        "result": {
            "slots": [
                {
                    "id": "wed-1300" if bookkeeping_matches else "fri-1000",
                    "time": "Wednesday 13:00" if values_match else "Tuesday 10:00",
                }
            ],
            "done": True,
            "decision": "book",
        }
    }
    if extra_action:
        payload["result"]["also"] = {"action": "cancel_booking", "booking_ref": "bk-123"}
    message = judge.JudgeInput(
        text_part="Booked: your delivery is confirmed for Wednesday at 13:00.\n",
        machine_part=judge.machine_part_text(payload),
        header_intent="response",
        subject="Re: delivery window",
        in_thread=True,
    )
    raw = build(
        sender="dispatch+t_window@agents.sender.test",
        to=["planner+t_window@agents.northwind.test"],
        subject=message.subject,
        intent="response",
        task="t_window",
        task_state="working",
        text=message.text_part,
        payload=payload,
        schema=f"{SCHEMA_BASE}response.json",
        in_reply_to="<t_window.1@agents.northwind.test>",
    ).as_bytes(policy=policy.SMTP)
    assert judge_input(raw, message.subject) == message
    body, truncated = judge.request_body(message, frozenset({"parts_agree"}), judge.DEFAULT_MODEL)
    assert json.loads(body["state"]["message"]["machine_part"]) == payload
    assert not truncated
