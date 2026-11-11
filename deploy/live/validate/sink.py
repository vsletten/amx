"""Validation-only SMTP sink: the MX of the fake outside domain client.example.test.

Stores each message as <n>.eml plus <n>.json (envelope, and whether the sender used STARTTLS),
so tools/live_validate.py can check what the live bundle delivered. Never on a live host.
"""

import json
import ssl
import threading
import time
from pathlib import Path

from aiosmtpd.controller import Controller

OUT = Path("/out")


class Sink:
    async def handle_DATA(self, server, session, envelope):
        stamp = time.time_ns()
        (OUT / f"{stamp}.eml").write_bytes(envelope.original_content or envelope.content)
        record = {
            "mail_from": envelope.mail_from,
            "rcpt_tos": envelope.rcpt_tos,
            "tls": session.ssl is not None,
            "helo": session.host_name,
            "peer": session.peer[0],
        }
        (OUT / f"{stamp}.json").write_text(json.dumps(record), encoding="utf-8")
        return "250 2.0.0 stored"


context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain("/tls/sink.pem", "/tls/sink-key.pem")
Controller(Sink(), hostname="0.0.0.0", port=25, tls_context=context, decode_data=False).start()
threading.Event().wait()
