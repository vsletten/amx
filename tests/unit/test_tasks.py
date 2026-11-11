from __future__ import annotations

import pytest

from amx.sdk import Agent
from amx.tasks import mint_token, valid_token


def test_minted_tokens_survive_the_gateways_case_folded_subaddress() -> None:
    # The milter and LMTP fold recipient addresses to lower case; the token must not change.
    tokens = {mint_token() for _ in range(500)}
    assert len(tokens) == 500
    for token in tokens:
        assert token == token.casefold()
        assert valid_token(token)
        assert len(token) == 18


@pytest.mark.parametrize(
    ("token", "valid"),
    [
        ("t_s06a_1f929cfd49", True),
        ("t_abc-def", True),
        ("t_gIdf_Xy_TPE-", False),  # the old token_urlsafe shape: breaks after case folding
        ("", False),
        ("_leading", False),
        ("t_" + "a" * 62, True),
        ("t_" + "a" * 63, False),
        ("t_a+b", False),
        ("t_a@b", False),
    ],
)
def test_valid_token(token: str, valid: bool) -> None:
    assert valid_token(token) is valid


def test_sdk_refuses_an_explicit_task_that_case_folding_would_change() -> None:
    agent = Agent("scheduler@agents.northwind.test", "smtp://127.0.0.1:2587", "secret")
    with pytest.raises(ValueError, match="lower-case"):
        agent.send(
            to="intake@agents.contoso.test",
            subject="Mixed case",
            intent="request",
            text="Never sent.",
            task="t_Mixed",
        )
