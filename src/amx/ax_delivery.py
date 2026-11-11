"""Durable AX custody, replay and completion; the worker owns a separate IMAP session.

One lock serializes send intents with recovery. AX notifications are hints; pending mail,
notices and status are the authoritative recovery sources. No model judgment owns state.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import imaplib
import json
import logging
import smtplib
import threading
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

from amx.adapters.ax import AxError, Contract, envelope, parse_reply, reply_cc
from amx.attachment_files import attachment_directory, load_files, remove_saved_file, save_file
from amx.attachments import Attachment
from amx.mailbox import HANDLED_KEYWORD, NOT_DELIVERED_KEYWORD
from amx.profile import parse
from amx.runner import REPORT_BACKOFF_MAX, bind, delivered_to, delivery_key
from amx.sdk import PreparedSubmission, Received

if TYPE_CHECKING:
    from amx.adapters.ax import AxPresence
    from amx.runner import Runner

LOG = logging.getLogger(__name__)
TERMINAL = {"acknowledged", "expired", "refused", "abandoned"}


def _encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _decode(raw: str) -> bytes:
    return base64.b64decode(raw)


def _uidvalidity(client) -> str:
    return str((client.untagged_responses.get("UIDVALIDITY") or [b""])[-1])


def _definitive(error: smtplib.SMTPResponseException | smtplib.SMTPRecipientsRefused) -> bool:
    """Whether submission refused for good: every code it answered is 5xx."""
    codes = (
        [error.smtp_code]
        if isinstance(error, smtplib.SMTPResponseException)
        else [value[0] for value in error.recipients.values()]
    )
    return bool(codes) and all(code >= 500 for code in codes)


def _refusal_text(error: smtplib.SMTPResponseException | smtplib.SMTPRecipientsRefused) -> str:
    """The gateway's answer as a person reads it: code and text, not a Python repr."""
    if isinstance(error, smtplib.SMTPResponseException):
        answers = [(error.smtp_code, error.smtp_error)]
    else:
        answers = list(error.recipients.values())
    return "; ".join(
        f"{code} {text.decode('utf-8', 'replace') if isinstance(text, bytes) else text}"
        for code, text in answers
    )


class AxDelivery:
    def __init__(
        self,
        runner: Runner,
        worker: AxPresence,
        *,
        ttl_seconds: int = 3600,
        credential_directories: Sequence[Path] = (),
    ):
        self.runner, self.worker = runner, worker
        self.log, self.endpoint = runner.handled, worker.endpoint
        self.lock = threading.RLock()
        self.ttl_seconds = ttl_seconds
        self.connected = False
        self.recover_at = 0.0
        self.sweep_at = 0.0
        self.client = None
        self.skipped: set[str] = set()
        self.credential_directories = tuple(credential_directories)

    def offer(self, client, uid: str, raw: bytes) -> bool | None:
        """True: AX owns it, False: retry AX, None: fallback may take it."""
        with self.lock, self._offer_files(delivery_key(raw)) as created:
            key = delivery_key(raw)
            record = self.log.ax_record(key)
            if record and record["state"] not in {"expired", "rejected"}:
                if record["state"] == "sending":
                    # Uncertain acceptance remains fenced from fallback even when offline.
                    return self._send(record, client, uid)
                return True
            if not self.connected or self.worker.presence._offline():
                # Presence can disappear after Runner.handle's preflight. This
                # is deferral to MCP, never permission to invoke --handler.
                # Release only a definitively unsubmitted provisional claim;
                # earlier accepted/uncertain AX custody must stay fenced.
                if record is None or (record["state"] == "rejected" and not record.get("ids")):
                    with self.runner.custody.locked() as state:
                        if state["claims"].get(key) == "runner":
                            del state["claims"][key]
                return False
            inbound = bind(raw)
            contract = self.worker.child.contract
            if contract == Contract.INTERIM and (
                inbound.lane not in {"agent", "system"} or inbound.tainted
            ):
                return self._fallback(key)
            if record and (record["state"] == "expired" or record.get("ids")):
                record.update(state="sending", operation="resend", parent=record["message_id"])
            else:
                parent = self.log.ax_parent(inbound.task)
                if parent:
                    try:
                        prior = self.endpoint.delivery_status(parent)["message"]
                        state = prior["status"]
                    except AxError as error:
                        if "not found" not in str(error) and "no such message" not in str(error):
                            LOG.warning("AX thread lookup deferred: %s", error)
                            return False
                        parent = None
                    else:
                        if state in TERMINAL or prior.get("reply_depth", 0) >= 8:
                            parent = None
                # Complete fallible broker preflight before creating any local files.
                # A transient thread lookup must leave nothing for the next retry to duplicate.
                directory = attachment_directory(self.runner.handled.path.parent, inbound.task)
                attachments = []
                for part in inbound.attachments:
                    metadata = part.metadata()
                    path = save_file(part, directory)
                    created.append(path)
                    attachments.append({**metadata, "path": str(path)})
                text, data, provenance = envelope(
                    inbound,
                    delivered_to(raw),
                    contract,
                    agent_address=self.runner.agent.address,
                    attachments=attachments,
                )
                record = {
                    "key": key,
                    "raw": _encode(raw),
                    "task": inbound.task,
                    "text": text,
                    "data": data,
                    "provenance": provenance,
                    "operation": "follow_up" if parent else "send",
                    "parent": parent,
                    "state": "sending",
                    "attempt": 0,
                    "ids": [],
                    "client_id": "amx_" + hashlib.sha256(key.encode()).hexdigest()[:40],
                    "ttl": self.ttl_seconds,
                    "target": self.worker.presence.target,
                    "binding": self._binding(),
                }
            record.update(uid=uid, uidvalidity=_uidvalidity(client))
            # The full immutable request is durable BEFORE AX can accept it.
            self.log.ax_save(record)
            return self._send(record, client, uid)

    @contextlib.contextmanager
    def _offer_files(self, key: str):
        """Rollback only this attempt's exclusive saves until the request is durable."""
        before = self.log.ax_record(key)
        created: list[Path] = []
        try:
            yield created
        except BaseException:
            # ax_save can commit and then raise. Never delete files a durable request
            # (or an uncertain broker send following it) already references.
            if self.log.ax_record(key) == before:
                for path in reversed(created):
                    remove_saved_file(path)
            raise

    def _fallback(self, key: str) -> None:
        # Uncertain sends never reach this definitive non-acceptance path.
        if self.runner.handler is None:
            with self.runner.custody.locked() as state:
                state["claims"].pop(key, None)
        if self.runner.handler is None and key not in self.skipped:
            LOG.info("AX: copy left untaken (no eligible target/fallback): %s", key)
            self.skipped.add(key)
        return None

    def _park(self, record: dict, client, uid: str, reason: str) -> bool:
        """Settle a copy the target refused under its external policy, as a refusal after AX
        acceptance is settled: a 5.7.1 policy refusal for its sender, a finished record, and the
        copy kept in the mailbox ($AmxHandled, $AmxNotDelivered), never retried or handed to a
        fallback handler. The outcome comes first, so if flagging fails the runner's own pass
        for recorded outcomes reports and flags it."""
        self.log.record(
            record["key"],
            f"refused AX external policy ({reason or 'no reason given'})",
            self.runner._refusal(_decode(record["raw"]), "5.7.1", "policy"),
        )
        record.update(state="terminal", finished=True)
        self.log.ax_save(record)
        with self.runner.custody.locked() as state:
            if state["claims"].get(record["key"]) == "runner":
                del state["claims"][record["key"]]
        try:
            self.runner._flag(client, uid, f"{HANDLED_KEYWORD} {NOT_DELIVERED_KEYWORD}")
        except (OSError, imaplib.IMAP4.error) as error:
            LOG.warning("AX: cannot flag refused UID %s yet (the next pass does): %s", uid, error)
        LOG.warning(
            "AX: %s refused UID %s under its external policy (%s); kept in the mailbox, marked %s",
            record["target"],
            uid,
            reason or "no reason given",
            NOT_DELIVERED_KEYWORD,
        )
        return True

    def _binding(self) -> dict:
        child = self.worker.child
        return {
            "home": str(child.home),
            "contract": str(child.contract),
            "name": child.name if child.contract == Contract.V1 else child.interim_name,
        }

    def _check_binding(self, record: dict) -> None:
        if record["binding"] != self._binding():
            raise AxError(
                "AX custody belongs to another AX_HOME/name/contract; "
                "drain outstanding deliveries before changing the relay binding"
            )

    def _send(self, record: dict, client, uid: str) -> bool | None:
        self._check_binding(record)
        if not self.connected:
            self.runner._untake(client, uid)
            return False
        self.runner._flag(client, uid, "\\Seen")
        client_id = record["client_id"]
        if record["attempt"]:
            client_id += f"_r{record['attempt']}"
        try:
            if record["operation"] == "resend":
                result = self.endpoint.resend_message(record["parent"], client_id, record["ttl"])
            else:
                fields = {"data": record["data"], "provenance": record["provenance"]}
                if record["operation"] == "follow_up":
                    result = self.endpoint.follow_up(
                        record["parent"], record["text"], client_id, record["ttl"], **fields
                    )
                else:
                    result = self.endpoint.send_message(
                        record["target"],
                        record["text"],
                        client_id,
                        record["ttl"],
                        **fields,
                    )
            message = result["message"]
            self._accepted(record, message)
        except AxError as error:
            self.runner._untake(client, uid)
            details = error.details or {}
            if (
                isinstance(details, dict)
                and details.get("code") == "external_policy"
                and details.get("rpc_code") == -32002
                and details.get("submission") == "not_submitted"
            ):
                record["state"] = "rejected"
                self.log.ax_save(record)
                if details.get("external") in {"verified", "all"}:
                    # The target takes external mail, only not this copy's provenance (say, an
                    # unverified sender to a session that takes verified mail only). Set this one
                    # copy aside; pausing the agent for it would refuse every later message and
                    # retry this one forever.
                    return self._park(record, client, uid, str(details.get("reason") or ""))
                # The owner closed the target to external mail: senders wait until it reopens.
                self.worker.presence.policy_blocked = True
                self.worker.presence.tick()
                return self._fallback(record["key"])
            if (
                record["operation"] == "follow_up"
                and isinstance(details, dict)
                and (
                    (
                        details.get("code") == "reply_depth_limit"
                        and details.get("submission") == "not_submitted"
                    )
                    or (
                        details.get("code") == "request_failed"
                        and details.get("message")
                        == "message is not eligible for a reply or follow-up"
                    )
                )
            ):
                # Both supported pins check sender/client_id BEFORE these exact
                # parent validations and storage. Even though the generic MCP
                # wrapper labels ineligibility outcome_unknown, this error proves
                # no acceptance. It can race the status preflight as a parent expires.
                record.update(operation="send", parent=None)
                self.log.ax_save(record)
                return self._send(record, client, uid)
            LOG.warning("AX send deferred (handler budget unchanged): %s", error)
            return False
        record["message_id"] = message["message_id"]
        record["ids"] = list(dict.fromkeys([*record["ids"], message["message_id"]]))
        # Do not finish here, even if the acceptance response already says acknowledged.
        record["state"] = "queued"
        self.log.ax_save(record, thread=True)
        self.recover_at = 0
        return True

    def _accepted(self, record: dict, message: dict) -> None:
        """Fault-injection seam after broker acceptance, before the local ID write."""

    def event(self, event: dict) -> None:
        if event.get("method") == "amx/wake":
            self.recover_at = 0
        elif event.get("method") == "notifications/ax/message":
            # Validate actual notification shape. Recovery reads durable broker state;
            # it also reconciles replies before an acknowledgment notice finishes a copy.
            params = event["params"]
            if params["meta"]["kind"] in {"message", "ax_delivery_status"}:
                content = json.loads(params["content"])
                if not isinstance(content, dict):
                    raise AxError("invalid AX notification content")
                self.recover_at = 0

    def _imap(self):
        if self.client is None:
            client = self.runner._connect()
            try:
                client.login(self.runner.login.username, self.runner.login.password)
                status, detail = client.select("INBOX")
                if status != "OK":
                    raise imaplib.IMAP4.error(f"cannot select INBOX: {detail!r}")
            except BaseException:
                client.logout()
                raise
            self.client = client
        return self.client

    def _copy(self, record: dict) -> tuple[object, str] | None:
        client = self._imap()
        # Refresh selection so a rebuilt mailbox changes UIDVALIDITY on this connection too.
        status, detail = client.select("INBOX")
        if status != "OK":
            raise imaplib.IMAP4.error(f"cannot select INBOX: {detail!r}")
        if record["uidvalidity"] == _uidvalidity(client):
            status, fetched = client.uid("FETCH", record["uid"], "(BODY.PEEK[])")
            if status != "OK":
                raise imaplib.IMAP4.error("AX copy fetch failed")
            raw = next((row[1] for row in fetched if isinstance(row, tuple)), None)
            if raw is not None and delivery_key(raw) == record["key"]:
                return client, record["uid"]
        # Search candidates, then compare the COMPLETE delivery identity (recipient + ID).
        status, rows = client.uid("SEARCH", None, "UNDELETED")
        if status != "OK":
            raise imaplib.IMAP4.error("AX copy identity search failed")
        for uid in (rows[0] or b"").split():
            status, fetched = client.uid("FETCH", uid, "(BODY.PEEK[])")
            if status != "OK":
                raise imaplib.IMAP4.error("AX copy identity fetch failed")
            raw = next((row[1] for row in fetched if isinstance(row, tuple)), None)
            if raw is not None and delivery_key(raw) == record["key"]:
                record.update(uid=uid.decode(), uidvalidity=_uidvalidity(client))
                self.log.ax_save(record)
                return client, uid.decode()
        return None

    def step(self) -> None:
        now = self.worker.presence.clock()
        if not self.connected or now < self.recover_at:
            return
        try:
            with self.lock:
                for record in self.log.ax_records():
                    if not record.get("finished") and (
                        record["state"] != "rejected" or record.get("ids")
                    ):
                        self._check_binding(record)
                # Recover acceptance-before-record intents before matching any incoming reply.
                for record in self.log.ax_records():
                    if record["state"] == "sending" and (copy := self._copy(record)):
                        self._send(record, *copy)
                for reply in self.log.ax_replies():
                    record = self.log.ax_lookup(reply["message"].get("in_reply_to", ""))
                    if reply["state"] != "done" or (record and record["state"] != "complete"):
                        self._reply(reply["message"])
                cursor = 0
                while True:
                    page = self.endpoint.list_pending(cursor)
                    for message in page["messages"]:
                        # Queued content has not been offered and cannot be fetched yet.
                        if message["status"] != "queued":
                            self._reply(self.endpoint.get_message(message["message_id"]))
                    cursor = page.get("next_after_seq", 0)
                    if not cursor:
                        break
                # Pending replies were reconciled FIRST: AX reply atomically acks parent.
                while True:
                    notices = self.endpoint.list_notifications()["notifications"]
                    if not notices:
                        break
                    for notice in notices:
                        record = self.log.ax_lookup(notice["message_id"])
                        if record:
                            self._status(record, notice["message_id"], notice["status"])
                        self.endpoint.ack_notification(notice["notification_id"])
                if now >= self.sweep_at:
                    for record in self.log.ax_records():
                        if record["state"] in {
                            "queued",
                            "content_served",
                            "terminal",
                        } and not record.get("finished"):
                            status = self.endpoint.delivery_status(record["message_id"])
                            self._status(record, record["message_id"], status["message"]["status"])
                    self.sweep_at = now + (
                        300 if self.worker.child.contract == Contract.INTERIM else 60
                    )
                # Replay completion effects after lost flags/notice acknowledgments.
                for record in self.log.ax_records():
                    if record["state"] in {"complete", "terminal", "expired"}:
                        self._effects(record)
                self.recover_at = now + 60
        except (OSError, imaplib.IMAP4.error):
            self.close()
            self.recover_at = now + 5
            LOG.exception("AX worker IMAP effects deferred")
        except Exception:
            self.recover_at = now + 5
            raise

    def _reply(self, message: dict) -> None:
        message_id = message["message_id"]
        record = self.log.ax_lookup(message.get("in_reply_to", ""))
        if record is None:
            LOG.info("AX unrelated local message acknowledged, no amx send: %s", message_id)
            self.endpoint.ack_message(message_id)
            return
        reply = self.log.ax_reply(message_id)
        if reply is None:
            reply = {"message_id": message_id, "message": message, "state": "new"}
            self.log.ax_save_reply(reply)
        if reply["state"] in {"new", "prepared", "temporary", "uncertain"}:
            try:
                try:
                    self._submit_reply(reply, message, record)
                except (smtplib.SMTPResponseException, smtplib.SMTPRecipientsRefused) as error:
                    if not reply.get("cc") or reply.get("sender_only") or not _definitive(error):
                        raise
                    # SH-46: a Cc the gateway refuses must not cost the owner the answer. Nothing
                    # was sent, so the reply goes again to the sender alone, saying why.
                    LOG.warning("AX reply-all refused (%s); sending to the sender alone", error)
                    prepared = reply.pop("prepared", None)
                    if prepared is not None:
                        # The sender-only rebuild changes headers/text, not attached bytes.
                        reply["attachment_source"] = prepared["raw"]
                    reply.update(
                        state="new",
                        sender_only=True,
                        refused_cc=reply["cc"],
                        refusal=_refusal_text(error),
                    )
                    self.log.ax_save_reply(reply)
                    self._submit_reply(reply, message, record)
            except (smtplib.SMTPResponseException, smtplib.SMTPRecipientsRefused) as error:
                if not _definitive(error):
                    reply["state"] = "temporary"
                    self.log.ax_save_reply(reply)
                    raise AxError(f"temporary SMTP reply rejection: {error}") from error
                reply.update(state="rejected", error=str(error))
                LOG.warning("AX reply definitively rejected by submission: %s", error)
            except (OSError, smtplib.SMTPException) as error:
                reply.update(state="uncertain", error=str(error))
                self.log.ax_save_reply(reply)
                raise AxError(f"uncertain SMTP reply acceptance: {error}") from error
            except (ValueError, TypeError, KeyError) as error:
                reply.update(state="rejected", error=str(error))
                LOG.warning("AX reply invalid: %s", error)
            else:
                reply["state"] = "submitted"
            self.log.ax_save_reply(reply)
        if reply["state"] != "done":
            self.endpoint.ack_message(message_id)
            reply["state"] = "done"
            self.log.ax_save_reply(reply)
        record["state"] = "complete"
        self.log.ax_save(record)
        self._effects(record)

    def _submit_reply(self, reply: dict, message: dict, record: dict) -> None:
        if "prepared" in reply:
            prepared = reply["prepared"]
            self.runner.agent.submit_prepared(
                PreparedSubmission(
                    prepared["sender"],
                    tuple(prepared["recipients"]),
                    _decode(prepared["raw"]),
                )
            )
            return
        fields = parse_reply(message)

        def prepare(prepared: PreparedSubmission):
            reply["prepared"] = {
                "sender": prepared.sender,
                "recipients": list(prepared.recipients),
                "raw": _encode(prepared.raw),
            }
            reply["state"] = "prepared"
            self.log.ax_save_reply(reply)

        inbound = bind(_decode(record["raw"]))
        text = fields.text
        if reply.get("sender_only"):
            cc: tuple[str, ...] = ()
            text += (
                f"\n\n[amx: this reply was meant to reach {', '.join(reply['refused_cc'])} too, "
                f"but the gateway refused that ({reply['refusal']}), so it went to you alone.]"
            )
        else:
            # The owner's mail is answered reply-all (SH-46).
            cc = reply_cc(inbound, self.runner.agent.address)
        reply["cc"] = list(cc)
        if "attachment_source" in reply:
            attachments = tuple(
                Attachment(part.filename, part.content, part.declared_type)
                for part in parse(_decode(reply["attachment_source"])).attachments
            )
        else:
            attachments = load_files(
                fields.attachments,
                max_bytes=self.runner.agent.max_bytes,
                forbidden=(self.runner.handled.path.parent, *self.credential_directories),
            )
        Received(self.runner.agent, inbound).reply(
            **{**asdict(fields), "text": text, "attachments": attachments},
            cc=list(cc) or None,
            prepare=prepare,
        )

    def _status(self, record: dict, message_id: str, state: str) -> None:
        if message_id != record.get("message_id") or record["state"] == "complete":
            return  # stale notice from a previous expired attempt
        if state == "acknowledged":
            record["state"] = "complete"
        elif state == "expired":
            if record["state"] != "expired":
                record["attempt"] += 1
            record["state"] = "expired"
        elif state in {"refused", "abandoned"}:
            status, reason = (
                ("5.7.1", "policy") if state == "refused" else ("5.3.0", "handler-failed")
            )
            self.log.record(
                record["key"],
                f"refused AX {state}",
                self.runner._refusal(_decode(record["raw"]), status, reason),
            )
            record["state"] = "terminal"
        else:
            record["state"] = "content_served" if state == "content_served" else "queued"
        self.log.ax_save(record)
        self._effects(record)

    def _effects(self, record: dict) -> None:
        if record.get("finished"):
            return
        if record["state"] == "complete":
            # Outcome precedes flags, so a concurrent IMAP pass cannot run fallback.
            self.log.record(record["key"], "handled AX")
            if copy := self._copy(record):
                self.runner._flag(*copy, HANDLED_KEYWORD)
                record["finished"] = True
                self.log.ax_save(record)
        elif record["state"] == "expired":
            if copy := self._copy(record):
                self.runner._untake(*copy)
        elif record["state"] == "terminal":
            pending = self.log.unanswered_refusal(record["key"])
            now = self.runner.clock()
            if pending and now < pending.due <= now + REPORT_BACKOFF_MAX:
                return
            if (copy := self._copy(record)) and self.runner.handle(*copy, _decode(record["raw"])):
                record["finished"] = True
                self.log.ax_save(record)

    def close(self) -> None:
        if self.client is not None:
            with contextlib.suppress(OSError, imaplib.IMAP4.error):
                self.client.logout()
            self.client = None
