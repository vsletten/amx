"""Keep legacy remote-handler acceptance independent of the AX target fixture."""

from __future__ import annotations

import os

import pytest

from scenarios.support import compose, compose_exec


@pytest.fixture(scope="module", autouse=True)
def remote_handler_configuration(request):
    if "test_s18_" not in request.module.__name__:
        yield
        return
    previous = os.environ.get("AMX_RUNNER_AX_TARGET")
    os.environ["AMX_RUNNER_AX_TARGET"] = ""
    try:
        compose("up", "-d", "--no-deps", "runner-ct")
        compose_exec(
            "runner-ct",
            "/app/.venv/bin/amx-runner",
            "--agent=outpost@agents.contoso.test",
            "--submit=smtp://edge-ct:2587",
            "--ca=/tls/dev-ca.pem",
            "control",
            "resume",
        )
        yield
    finally:
        if previous is None:
            os.environ.pop("AMX_RUNNER_AX_TARGET", None)
        else:
            os.environ["AMX_RUNNER_AX_TARGET"] = previous
        compose("up", "-d", "--no-deps", "runner-ct")
