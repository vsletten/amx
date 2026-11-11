from __future__ import annotations

from pathlib import Path

from amx.profile import Inbound
from amx.runtime import Context, HandlerRegistry, Refuse, TryLater

CORPUS = Path("spec/corpus")


def test_registry_dispatches_sync_handler() -> None:
    seen: list[str] = []

    def handler(message: Inbound, context: Context) -> None:
        seen.append(f"{context.agent}:{message.task}")

    from amx.profile import parse

    message = parse((CORPUS / "01-request.eml").read_bytes())
    registry = HandlerRegistry()
    registry.register("intake", handler)
    registry.dispatch("intake", message, Context("intake", {}))
    assert seen == [f"intake:{message.task}"]
    assert registry.depth("intake") == 0


def test_registry_preserves_typed_handler_failures() -> None:
    from amx.profile import parse

    message = parse((CORPUS / "01-request.eml").read_bytes())
    registry = HandlerRegistry()

    def later(_message: Inbound, _context: Context) -> None:
        raise TryLater("busy")

    registry.register("intake", later)
    try:
        registry.dispatch("intake", message, Context("intake", {}))
    except TryLater as error:
        assert str(error) == "busy"
    else:
        raise AssertionError("TryLater was not propagated")

    try:
        registry.dispatch("missing", message, Context("missing", {}))
    except Refuse as error:
        assert error.code == "5.1.1"
    else:
        raise AssertionError("Refuse was not raised")


def test_context_routes_send_and_reply_through_bound_submission_callbacks() -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def send(**message: object) -> str:
        calls.append(("send", message))
        return "sent"

    def reply(**message: object) -> str:
        calls.append(("reply", message))
        return "replied"

    context = Context("intake", {}, send_message=send, reply_message=reply)
    assert context.send(to="pat@plainmail.test", intent="request", text="Hello") == "sent"
    assert context.reply(intent="response", text="Done") == "replied"
    assert calls == [
        ("send", {"to": "pat@plainmail.test", "intent": "request", "text": "Hello"}),
        ("reply", {"intent": "response", "text": "Done"}),
    ]


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_queued_mode_runs_jobs_on_workers_and_bounds_the_queue() -> None:
    import threading

    registry = HandlerRegistry()
    registry.register("intake", "mailbox-only", mode="queued", watermark=2, workers=1)
    gate = threading.Event()
    ran: list[int] = []

    def job(number: int):
        def run() -> None:
            gate.wait(5)
            ran.append(number)

        return run

    assert registry.mode("intake") == "queued"
    assert registry.submit("intake", job(1))
    assert registry.submit("intake", job(2))
    assert registry.depth("intake") == 2
    assert registry.full("intake")
    assert not registry.submit("intake", job(3)), "a full bounded queue must refuse"
    assert registry.submit("intake", job(4), force=True), "recovery bypasses the bound"
    assert registry.depth("intake") == 3
    gate.set()
    registry.join("intake")
    assert ran == [1, 2, 4]
    assert registry.depth("intake") == 0
    registry.stop()


def test_queued_worker_survives_a_failing_job() -> None:
    registry = HandlerRegistry()
    registry.register("intake", "mailbox-only", mode="queued", watermark=2)
    ran: list[str] = []

    def boom() -> None:
        raise RuntimeError("job failed")

    assert registry.submit("intake", boom)
    assert registry.submit("intake", lambda: ran.append("after"))
    registry.join("intake")
    assert ran == ["after"]
    registry.stop()


def test_sync_submit_is_rejected_and_unknown_mode_is_invalid() -> None:
    registry = HandlerRegistry()
    registry.register("intake", "mailbox-only")
    try:
        registry.submit("intake", lambda: None)
    except ValueError as error:
        assert "not in queued mode" in str(error)
    else:
        raise AssertionError("sync agents have no queue")
    try:
        registry.register("other", "mailbox-only", mode="batch")  # type: ignore[arg-type]
    except ValueError as error:
        assert "unsupported handler mode" in str(error)
    else:
        raise AssertionError("unknown mode accepted")


def test_rcpt_admissions_count_toward_depth_until_settled_released_or_expired() -> None:
    from amx.runtime import RESERVATION_TTL, Admission

    clock = FakeClock()
    registry = HandlerRegistry(clock=clock)
    registry.register("intake", "mailbox-only", mode="queued", watermark=2)

    first = registry.reserve("intake")
    second = registry.reserve("intake")
    assert registry.depth("intake") == 2
    registry.release(second)
    assert registry.depth("intake") == 1

    registry.bind(first, " <one@test> ")
    other = Admission("intake", "<other@test>")
    registry.settle(other)
    assert registry.depth("intake") == 1, "settling must match the exact Message-ID only"
    registry.settle(Admission("intake", "<one@test>"))
    assert registry.depth("intake") == 0

    stale = registry.reserve("intake")
    registry.bind(stale, None)
    clock.now += RESERVATION_TTL + 1
    assert registry.depth("intake") == 0, "an admission that never reaches LMTP expires"


def test_submit_turns_the_admission_into_the_queued_slot_atomically() -> None:
    import threading

    from amx.runtime import Admission

    registry = HandlerRegistry()
    registry.register("intake", "mailbox-only", mode="queued", watermark=2)
    gate = threading.Event()
    registry.bind(registry.reserve("intake"), "<a@test>")
    registry.bind(registry.reserve("intake"), "<b@test>")
    assert registry.depth("intake") == 2

    admission = Admission("intake", "<a@test>")
    assert registry.submit("intake", lambda: gate.wait(5), admission=admission)
    assert admission.settled
    assert registry.depth("intake") == 2, "the admission became the slot; depth never dipped"
    registry.settle(admission)
    assert registry.depth("intake") == 2, "settling twice is a no-op"
    gate.set()
    registry.join("intake")
    assert registry.depth("intake") == 1
    registry.stop()


def test_sync_dispatch_turns_the_admission_into_the_running_slot() -> None:
    from amx.profile import parse
    from amx.runtime import Admission

    registry = HandlerRegistry()
    depths: list[int] = []
    registry.register("intake", lambda _message, _context: depths.append(registry.depth("intake")))
    registry.bind(registry.reserve("intake"), "<sync@test>")
    admission = Admission("intake", "<sync@test>")
    message = parse((CORPUS / "01-request.eml").read_bytes())
    registry.dispatch("intake", message, Context("intake", {}), admission=admission)
    assert depths == [1]
    assert registry.depth("intake") == 0


def test_a_remote_agent_has_no_handler_here_and_its_backlog_is_its_mailbox() -> None:
    import pytest

    from amx.profile import parse

    counts = iter([3, RuntimeError("mailhost down")])

    def backlog() -> int:
        value = next(counts)
        if isinstance(value, Exception):
            raise value
        return value

    registry = HandlerRegistry()
    registry.register("outpost", "mailbox-only", mode="remote", watermark=2, backlog=backlog)
    assert registry.mode("outpost") == "remote"
    assert not registry.full("outpost")
    message = parse((CORPUS / "01-request.eml").read_bytes())
    registry.dispatch("outpost", message, Context("outpost", {}))  # files only; runs nothing
    assert registry.depth("outpost") == 0, "depth never reads the mailhost"
    assert registry.backlog("outpost") == 3
    assert registry.backlog("outpost") == 2, "an unreadable backlog counts as full"
    assert registry.backlog("intake") == 0
    with pytest.raises(ValueError, match="runs on its own host"):
        registry.register("rogue", lambda _message, _context: None, mode="remote")


def test_load_handler_names_a_module_function() -> None:
    import pytest

    from amx.runtime import load_handler

    assert load_handler("amx.examples.echo:handle").__name__ == "handle"
    with pytest.raises(ValueError, match="module:function"):
        load_handler("amx.examples.echo")
    with pytest.raises(TypeError, match="not callable"):
        load_handler("amx.runtime:RESERVATION_TTL")
