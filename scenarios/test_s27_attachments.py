"""S27 / SH-42: disposable agents exchange a PDF; submission refuses a disguised ELF.

Run only under the repository's isolated Compose suite, never against live agents.
"""

from __future__ import annotations

import json
import smtplib
import ssl
import uuid
from email import policy
from pathlib import Path

import pytest

from amx.attachments import Attachment
from amx.custody import Custody
from amx.mcp_server import AgentTools, ImapAccount, Mailbox
from amx.profile import build, parse
from amx.sdk import Agent
from amx.testkit import wait_for_message
from scenarios.support import DEV_TLS_CA
from scenarios.test_s19_agent_registration import CT_REGISTRY, IMAP, SUBMISSION, _ct, _rcpt, _wait

pytestmark = pytest.mark.integration
PDF = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF\n"


def test_s27_pdf_reaches_agent_and_saves_while_disguised_executable_is_refused(tmp_path):
    suffix = uuid.uuid4().hex[:8]
    names = [f"file-{suffix}-{letter}" for letter in ("a", "b")]
    addresses = [f"{name}@agents.contoso.test" for name in names]
    bundles = []
    try:
        for name, address in zip(names, addresses, strict=True):
            bundle_path = tmp_path / f"{name}.json"
            added = _ct(
                "agent",
                "add",
                name,
                "--live",
                "--bundle",
                str(bundle_path),
                "--imap",
                f"{IMAP[0]}:{IMAP[1]}",
                "--submission",
                f"smtp://{SUBMISSION[0]}:{SUBMISSION[1]}",
            )
            assert added.returncode == 0, "attachment fixture registration failed"
            bundles.append(json.loads(bundle_path.read_text()))
            _wait(lambda address=address: _rcpt(address)[0] == 250, 30, "fixture did not reload")
        agent = Agent(
            addresses[0],
            f"smtp://{SUBMISSION[0]}:{SUBMISSION[1]}",
            bundles[0]["token"],
            tls_ca_file=str(DEV_TLS_CA),
        )
        sent = agent.send(
            to=addresses[1],
            subject="S27 PDF",
            text="Please read the attached file.",
            intent="request",
            attachments=[Attachment("report.pdf", PDF)],
        )
        delivered = wait_for_message(
            IMAP[0],
            addresses[1],
            bundles[1]["password"],
            lambda message: message.get("Message-ID") == sent.message_id,
            port=IMAP[1],
        )
        incoming = parse(delivered.as_bytes(policy=policy.SMTP))
        assert len(incoming.attachments) == 1
        assert incoming.attachments[0].type == "application/pdf"
        assert incoming.attachments[0].content == PDF
        reader = AgentTools(
            Agent(
                addresses[1],
                f"smtp://{SUBMISSION[0]}:{SUBMISSION[1]}",
                bundles[1]["token"],
                tls_ca_file=str(DEV_TLS_CA),
            ),
            Mailbox(ImapAccount(*IMAP, addresses[1], bundles[1]["password"])),
            custody=Custody(addresses[1], directory=tmp_path / "custody"),
            state_directory=tmp_path / "reader",
        )
        saved = reader.save_attachment(sent.message_id, 0)
        assert Path(saved["path"]).read_bytes() == PDF
        assert saved["type"] == "application/pdf"
        # Bypass the SDK's earlier refusal to prove the gateway also examines true bytes.
        raw = build(
            sender=addresses[0],
            to=addresses[1],
            subject="S27 blocked file",
            intent="request",
            task=f"t_s27_{suffix}",
            task_state="submitted",
            text="Fixture.",
            attachments=[Attachment("not-a-pdf.pdf", b"\x7fELFfixture", "application/pdf")],
        ).as_bytes(policy=policy.SMTP)
        with smtplib.SMTP(*SUBMISSION, timeout=15) as client:
            client.starttls(context=ssl.create_default_context(cafile=str(DEV_TLS_CA)))
            client.login(names[0], bundles[0]["token"])
            with pytest.raises(smtplib.SMTPDataError) as refused:
                client.sendmail(addresses[0], [addresses[1]], raw)
            assert refused.value.smtp_code == 552
            assert b"5.3.4" in refused.value.smtp_error
        print(
            "S27: typed PDF read and saved byte-identically; disguised ELF refused with 552 5.3.4"
        )
    finally:
        for name in names:
            if (CT_REGISTRY / "agents" / f"{name}.yaml").exists():
                assert _ct("agent", "remove", name).returncode == 0
                assert _ct("agent", "remove", name, "--purge", "--now").returncode == 0
