"""Sealed SH-20 canary: capture any unexpected private outbound delivery."""

import threading
import time
from pathlib import Path

from aiosmtpd.controller import Controller


class Sink:
    async def handle_DATA(self, server, session, envelope):
        (Path("/out") / f"{time.time_ns()}.eml").write_bytes(envelope.original_content)
        return "250 2.0.0 stored"


Controller(Sink(), hostname="0.0.0.0", port=25).start()
threading.Event().wait()
