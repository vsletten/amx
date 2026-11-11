from __future__ import annotations

import argparse
import dataclasses
import json
import socket
from pathlib import Path
from typing import Any

import pytest
import yaml

from amx import holds
from amx.adapters import stalwart
from amx.adapters.stalwart import (
    Site,
    ensure_mailboxes,
    expression,
    hold_folders,
    hold_parents,
    master_login,
    phases,
    plan_text,
    read_dev_users,
    render_plan,
    shared_name,
    site_users,
)
from amx.config import GatewayConfig, LimitsConfig, MailboxConfig

ROOT = Path(__file__).resolve().parents[2]

SITE = Site(
    domain="contoso.test",
    agent_domain="agents.contoso.test",
    hostname="mail.contoso.test",
    gateway_host="gateway-ct",
    gateway_ip="172.30.0.21",
)
DEV_USERS = """
# DEVELOPMENT ONLY.
victor@northwind.test|dev-victor
ops@contoso.test|dev-ops
Intake@agents.contoso.test|dev-intake

gateway|dev-gateway
approver|dev-approver
"""


def _plan() -> list[dict[str, Any]]:
    users, masters = read_dev_users(DEV_USERS)
    return render_plan(SITE, users, masters)


def _operation(plan: list[dict[str, Any]], name: str) -> dict[str, Any]:
    (found,) = [operation for operation in plan if operation["object"] == name]
    return found


def test_dev_users_split_into_mail_users_and_master_logins() -> None:
    users, masters = read_dev_users(DEV_USERS)
    assert users == [
        ("victor@northwind.test", "dev-victor"),
        ("ops@contoso.test", "dev-ops"),
        ("intake@agents.contoso.test", "dev-intake"),
    ]
    assert masters == {"gateway": "dev-gateway", "approver": "dev-approver"}
    assert site_users(users, SITE) == users[1:]


def test_hold_folders_are_where_the_gateway_files_and_watches_holds() -> None:
    mailbox = MailboxConfig(
        host="mailhost-ct", hold_owner=SITE.hold_mailbox, hold_prefix=SITE.hold_prefix
    )
    gateway = GatewayConfig(
        domain="contoso.test",
        agent_domain="agents.contoso.test",
        data_dir=Path("/nonexistent"),
        agents={},
        trust=(),
        limits=LimitsConfig(),
        mailbox=mailbox,
    )
    queue = holds.hold_queue(gateway, "intake")
    assert (queue.mailbox, queue.own) == ("holds@contoso.test", False)
    assert hold_folders(SITE, "intake") == (queue.held, queue.approved, queue.rejected)
    assert hold_parents(SITE, "intake") == ("Holds", "Holds/intake")
    # How the agent and the approver see it: Stalwart's shared-folder namespace.
    assert shared_name(SITE, queue.held) == "Shared Folders/holds@contoso.test/Holds/intake/Held"
    assert holds.SENT_FOLDER in stalwart.SUBSCRIBED_FOLDERS


class _ComposeLoader(yaml.SafeLoader):
    """Reads compose.stalwart.yaml's !reset and !override tags as plain values."""


def _untagged(loader: yaml.SafeLoader, node: yaml.Node) -> Any:
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    return loader.construct_scalar(node)  # type: ignore[arg-type]


for _tag in ("!reset", "!override"):
    _ComposeLoader.add_constructor(_tag, _untagged)


def test_compose_gives_the_init_container_and_the_gateway_one_hold_layout() -> None:
    text = (ROOT / "deploy" / "compose.stalwart.yaml").read_text(encoding="utf-8")
    services = yaml.load(text, Loader=_ComposeLoader)["services"]
    arguments = dict(
        item.removeprefix("--").split("=", 1) for item in services["stalwart-init-ct"]["command"]
    )
    environment = services["gateway-ct"]["environment"]
    assert arguments["hold-owner"] == environment["AMX_MAILBOX_HOLD_OWNER"] == SITE.hold_mailbox
    assert arguments["hold-prefix"] == environment["AMX_MAILBOX_HOLD_PREFIX"] == SITE.hold_prefix


def test_mailhost_and_provisioner_use_the_same_verified_stalwart_release() -> None:
    # Docker Hub OCI index, verified with buildx imagetools inspect on 2026-10-15.
    image = (
        "stalwartlabs/stalwart:v0.16.25@sha256:"
        "74e5a7d55303ba525d939c6bf97ed4e010df7521f52d80afc22a815b66bd53f3"
    )
    deploy = ROOT / "deploy"
    services = yaml.load((deploy / "compose.stalwart.yaml").read_text(), Loader=_ComposeLoader)[
        "services"
    ]
    assert services["mailhost-ct"]["image"] == image
    assert f"FROM {image} AS stalwart" in (deploy / "stalwart" / "Dockerfile").read_text()


def test_expression_keeps_case_order() -> None:
    assert expression("'mx'", ("a", "'x'"), ("b", "'y'")) == {
        "else": "'mx'",
        "match": {"0": {"if": "a", "then": "'x'"}, "1": {"if": "b", "then": "'y'"}},
    }


def test_milter_runs_on_port_25_only_at_mail_rcpt_and_data_and_fails_closed() -> None:
    milter = _operation(_plan(), "MtaMilter")["value"]["milter-gateway"]
    # By IP: Stalwart resolves a milter host once, at startup, and drops one it cannot resolve.
    assert milter["hostname"] == "172.30.0.21"
    assert milter["port"] == 8890
    assert milter["stages"] == {"mail": True, "rcpt": True, "data": True}
    assert milter["enable"] == expression("false", ("local_port == 25", "true"))
    assert milter["tempFailOnError"] is True
    assert milter["protocolVersion"] == "v6"
    # The connect is bounded by timeoutCommand; replies (the judge at end of data) by timeoutData.
    assert (milter["timeoutCommand"], milter["timeoutData"]) == (5000, 60000)
    assert "timeoutConnect" not in milter  # never read; left at Stalwart's default


def test_agent_domain_routes_to_the_gateway_lmtp_and_keeps_task_sub_addresses() -> None:
    plan = _plan()
    route = _operation(plan, "MtaRoute")["value"]["route-gateway"]
    assert route == {
        "@type": "Relay",
        "name": "gateway",
        "description": "amx gateway LMTP (Postfix transport_maps)",
        "address": "gateway-ct",
        "port": 2424,
        "protocol": "lmtp",
        "implicitTls": False,
    }
    routing = _operation(plan, "MtaOutboundStrategy")["value"]["route"]
    # The agent domain is local too (its accounts hold the agents' mailboxes), so its rule
    # must come before the local-delivery rule.
    assert routing["match"]["1"] == {
        "if": "rcpt_domain == 'agents.contoso.test'",
        "then": "'gateway'",
    }
    assert routing["match"]["2"]["then"] == "'local'"
    domains = _operation(plan, "Domain")["value"]
    assert domains["domain-agents"]["subAddressing"] == {"@type": "Disabled"}
    assert domains["domain-agents"]["allowRelaying"] is True
    assert "subAddressing" not in domains["domain-site"]


def test_relaying_mirrors_postfix_mynetworks_and_test_domains_only() -> None:
    plan = _plan()
    relay = _operation(plan, "MtaStageRcpt")["value"]["allowRelaying"]
    assert relay["else"] == "false"
    # allowed-recipients.pcre's five domains, not every .test name (dead.test is not one).
    assert relay["match"]["0"]["if"] == (
        "is_ip_in_cidr(remote_ip, '172.30.0.0/24') && (rcpt_domain == 'northwind.test' || "
        "rcpt_domain == 'agents.northwind.test' || rcpt_domain == 'contoso.test' || "
        "rcpt_domain == 'agents.contoso.test' || rcpt_domain == 'plainmail.test')"
    )
    auth = _operation(plan, "MtaStageAuth")["value"]["require"]
    assert auth == expression(
        "local_port != 25 && !(local_port == 10025) && "
        "listener != 'sibling-in' && listener != 'sibling'"
    )


@pytest.mark.parametrize("people_milter_port", [0, 8892])
def test_people_smtp_auth_requires_tls(people_milter_port: int) -> None:
    users, masters = read_dev_users(DEV_USERS)
    site = dataclasses.replace(SITE, people_milter_port=people_milter_port)
    plan = render_plan(site, users, masters)
    auth = _operation(plan, "MtaStageAuth")["value"]
    if people_milter_port:
        # v0.16.25's default offers bearer-token AUTH before TLS. Protect tokens
        # as well as passwords; retain all native mechanisms after STARTTLS/465.
        assert auth["saslMechanisms"] == expression(
            "false", ("local_port != 25 && is_tls", "[plain, login, oauthbearer, xoauth2]")
        )
        settings, _accounts = phases(plan)
        assert _operation(settings, "MtaStageAuth")["value"] == auth
    else:
        assert "saslMechanisms" not in auth  # legacy dev hosts retain upstream defaults
    assert auth["mustMatchSender"] == expression("true")


def test_stalwart_does_no_sender_authentication_signing_or_spam_filtering() -> None:
    plan = _plan()
    sender_auth = _operation(plan, "SenderAuth")["value"]
    assert sender_auth["dkimSignDomain"] == expression("false")
    assert {value["else"] for key, value in sender_auth.items() if key != "dkimSignDomain"} == {
        "disable"
    }
    assert _operation(plan, "SpamSettings")["value"]["enable"] is False
    assert _operation(plan, "SpamPyzor")["value"] == {"enable": False}
    assert _operation(plan, "Asn")["value"] == {"@type": "Disabled"}


def test_oauth_clients_must_be_registered_before_a_redirect_uri_is_honoured() -> None:
    # CVE-2026-81036: without this, Stalwart (through v0.16.24) sends an authorization code to
    # any redirect_uri for any client id it does not recognise, and anyone may register a
    # client. The settings load at startup, so they belong to the settings phase, before the
    # restart.
    plan = _plan()
    assert _operation(plan, "OidcProvider") == {
        "@type": "update",
        "object": "OidcProvider",
        "value": {"requireClientRegistration": True, "anonymousClientRegistration": False},
    }
    settings, _accounts = phases(plan)
    assert "OidcProvider" in {operation["object"] for operation in settings}


def test_schedules_mirror_postfix_backoff_and_thirty_second_lifetime() -> None:
    schedules = _operation(_plan(), "MtaDeliverySchedule")["value"]
    assert set(schedules) == {"local", "remote", "dsn"}
    for schedule in schedules.values():
        assert schedule["retry"]["intervals"] == {
            "0": {"duration": 5000},
            "1": {"duration": 10000},
            "2": {"duration": 20000},
            "3": {"duration": 30000},
        }
        assert schedule["expiry"] == {"@type": "Ttl", "expire": 30000}


def test_accounts_are_site_users_one_master_the_approver_and_the_hold_owner() -> None:
    operation = _operation(_plan(), "Account")
    assert operation["matchOn"] == ["name", "domainId"]
    accounts = operation["value"]
    assert set(accounts) == {
        "account-ops-contoso-test",
        "account-intake-agents-contoso-test",
        "account-gateway-contoso-test",
        "account-approver-contoso-test",
        "account-holds-contoso-test",
    }
    intake = accounts["account-intake-agents-contoso-test"]
    assert (intake["name"], intake["domainId"]) == ("intake", "#domain-agents")
    assert accounts["account-ops-contoso-test"]["domainId"] == "#domain-site"
    assert intake["credentials"] == {"0": {"@type": "Password", "secret": "dev-intake"}}
    assert "permissions" not in accounts["account-ops-contoso-test"]
    permissions = accounts["account-gateway-contoso-test"]["permissions"]
    assert permissions["enabledPermissions"] == {"impersonate": True}
    # A Stalwart master acts as the owner, so the approver is an ordinary account. The upsert
    # takes impersonate away explicitly: an older volume gave it to the approver.
    approver = accounts["account-approver-contoso-test"]
    assert approver["permissions"] == stalwart.NOT_A_MASTER
    assert approver["permissions"]["disabledPermissions"] == {"impersonate": True}
    assert approver["credentials"] == {"0": {"@type": "Password", "secret": "dev-approver"}}
    # Only the gateway's master login opens the hold owner's mailbox, and it takes no mail.
    owner = accounts["account-holds-contoso-test"]
    assert "credentials" not in owner
    assert (owner["name"], owner["domainId"]) == ("holds", "#domain-site")
    assert owner["permissions"]["disabledPermissions"] == {
        "impersonate": True,
        "emailReceive": True,
    }


def test_the_hold_layout_is_checked_before_anything_is_applied() -> None:
    users, masters = read_dev_users(DEV_USERS)
    for site, message in (
        (dataclasses.replace(SITE, hold_owner="holds@northwind.test"), "is not on contoso"),
        (dataclasses.replace(SITE, hold_prefix="Holds/"), "must be a folder path with"),
        (dataclasses.replace(SITE, hold_prefix="Holds/{agent}"), "must be a folder path with"),
        (dataclasses.replace(SITE, hold_prefix="/Holds/{agent}/"), "must be a folder path with"),
    ):
        with pytest.raises(ValueError, match=message):
            render_plan(site, users, masters)
    users, masters = read_dev_users(DEV_USERS + "holds@contoso.test|x\n")
    with pytest.raises(ValueError, match="listed twice"):
        render_plan(SITE, users, masters)
    # Not in the agent domain: an agent that owned the queues could approve every one of them.
    in_agents = dataclasses.replace(SITE, hold_owner="Intake@Agents.Contoso.test")
    with pytest.raises(ValueError, match="is not on contoso"):
        render_plan(in_agents, *read_dev_users(DEV_USERS))


def test_the_same_local_part_in_both_domains_is_two_accounts_and_a_repeat_is_refused() -> None:
    users, masters = read_dev_users(DEV_USERS + "ops@agents.contoso.test|dev-ops-agent\n")
    accounts = _operation(render_plan(SITE, users, masters), "Account")["value"]
    assert accounts["account-ops-agents-contoso-test"]["domainId"] == "#domain-agents"
    assert accounts["account-ops-contoso-test"]["domainId"] == "#domain-site"
    users, masters = read_dev_users(DEV_USERS + "ops@contoso.test|again\n")
    with pytest.raises(ValueError, match="listed twice"):
        render_plan(SITE, users, masters)
    # Two addresses whose plan keys collide are named as such, not as a repeat.
    users, masters = read_dev_users(DEV_USERS + "a.b@contoso.test|x\na-b@contoso.test|y\n")
    with pytest.raises(ValueError, match=r"a-b@contoso\.test and a\.b@contoso\.test both make"):
        render_plan(SITE, users, masters)


def test_the_plan_owns_the_milter_and_allowed_ip_lists() -> None:
    plan = _operation(_plan(), "MtaMilter"), _operation(_plan(), "AllowedIp")
    # reconcile removes entries the plan no longer declares (a changed gateway IP).
    assert {operation["@type"] for operation in plan} == {"reconcile"}


def test_render_plan_refuses_missing_masters_or_users() -> None:
    users, masters = read_dev_users(DEV_USERS)
    with pytest.raises(ValueError, match="approver"):
        render_plan(SITE, users, {"gateway": "dev-gateway"})
    with pytest.raises(ValueError, match="no development users"):
        render_plan(SITE, [("pat@plainmail.test", "dev-pat")], masters)


def test_accounts_apply_after_a_restart_with_the_domains_they_name() -> None:
    plan = _plan()
    settings, accounts = phases(plan)
    assert "Account" not in {operation["object"] for operation in settings}
    assert [operation["object"] for operation in accounts] == ["Domain", "Account"]
    assert len(settings) + 1 == len(plan)


def test_plan_text_is_one_json_operation_per_line() -> None:
    plan = _plan()
    lines = plan_text(plan).splitlines()
    assert [json.loads(line) for line in lines] == plan


def test_master_login_is_stalwarts_percent_form() -> None:
    assert master_login("intake@agents.contoso.test", "gateway", SITE) == (
        "intake@agents.contoso.test%gateway@contoso.test"
    )


def _unquoted(name: str) -> str:
    return name[1:-1].replace('\\"', '"') if name.startswith('"') else name


class FakeStalwart:
    """What ensure_mailboxes sees of Stalwart's IMAP: folders, ACLs, and subscriptions."""

    def __init__(
        self,
        *,
        fail_create: str | None = None,
        ignore_setacl: bool = False,
        unsubscribable: str | None = None,
    ) -> None:
        self.folders: dict[str, set[str]] = {}
        self.acls: dict[str, dict[str, str]] = {}
        self.subscribed: dict[str, set[str]] = {}
        self.log: list[tuple[str, ...]] = []
        self.fail_create = fail_create
        self.ignore_setacl = ignore_setacl
        self.unsubscribable = unsubscribable

    def client(self) -> FakeSession:
        return FakeSession(self)


class FakeSession:
    def __init__(self, server: FakeStalwart) -> None:
        self.server = server
        self.user = ""

    def login(self, login: str, password: str) -> None:
        self.server.log.append(("login", login, password))
        self.user = login.partition("%")[0]

    def list(self) -> tuple[str, list[bytes | None]]:
        names = self.server.folders.setdefault(self.user, {"INBOX", "Sent", "Drafts", "Trash"})
        return "OK", [f'() "/" "{name}"'.encode() for name in sorted(names)] + [None]

    def create(self, folder: str) -> tuple[str, list[bytes]]:
        name = _unquoted(folder)
        self.server.log.append(("create", self.user, name))
        if name == self.server.fail_create:
            return "NO", [b"denied"]
        self.server.folders[self.user].add(name)
        return "OK", [b"Mailbox created."]

    def getacl(self, folder: str) -> tuple[str, list[bytes]]:
        name = _unquoted(folder)
        grants = self.server.acls.get(name, {})
        line = f'"{name}" "{self.user}" rliteswkxpa' + "".join(
            f' "{grantee}" {rights}' for grantee, rights in grants.items()
        )
        return "OK", [line.encode()]

    def setacl(self, folder: str, who: str, what: str) -> tuple[str, list[bytes]]:
        self.server.log.append(("setacl", _unquoted(folder), who, what))
        if not self.server.ignore_setacl:
            # Stalwart has one right for "s" and "w", and reports them in its own order.
            rights = set(what) | ({"s", "w"} if set(what) & {"s", "w"} else set())
            self.server.acls.setdefault(_unquoted(folder), {})[who] = "".join(sorted(rights))
        return "OK", [b"SETACL completed"]

    def deleteacl(self, folder: str, who: str) -> tuple[str, list[bytes]]:
        self.server.log.append(("deleteacl", _unquoted(folder), who))
        self.server.acls.get(_unquoted(folder), {}).pop(who, None)
        return "OK", [b"DELETEACL completed"]

    def subscribe(self, folder: str) -> tuple[str, list[bytes]]:
        name = _unquoted(folder)
        self.server.log.append(("subscribe", self.user, name))
        mine = self.server.subscribed.setdefault(self.user, set())
        if name in mine:
            return "NO", [b"Mailbox is already subscribed."]  # as Stalwart answers
        if name != self.server.unsubscribable:
            mine.add(name)
        return "OK", [b"done"]

    def lsub(self) -> tuple[str, list[bytes | None]]:
        names = sorted(self.server.subscribed.setdefault(self.user, {"Sent", "Drafts", "Trash"}))
        return "OK", [f'() "/" "{name}"'.encode() for name in names] + [None]

    def delete(self, folder: str) -> tuple[str, list[bytes]]:
        name = _unquoted(folder)
        self.server.log.append(("delete", self.user, name))
        self.server.folders.get(self.user, set()).discard(name)
        return "OK", [b"Mailbox deleted."]

    def logout(self) -> None:
        self.server.log.append(("logout", self.user))


USERS = ["ops@contoso.test", "intake@agents.contoso.test", "inspections@agents.contoso.test"]
QUEUE = "Shared Folders/holds@contoso.test/Holds/{agent}/{name}"


def _ensure(server: FakeStalwart, users: list[str] = USERS) -> dict[str, list[str]]:
    return ensure_mailboxes(
        server.client,  # type: ignore[arg-type,return-value]
        SITE,
        users,
        lambda user: master_login(user, "gateway", SITE),
        "dev-gateway",
    )


def _queue(agent: str) -> set[str]:
    return {QUEUE.format(agent=agent, name=name) for name in ("Held", "Approved", "Rejected")}


def test_ensure_mailboxes_builds_each_agents_queue_with_exact_rights() -> None:
    server = FakeStalwart()
    created = _ensure(server)
    assert created == {
        "holds@contoso.test": [
            "Holds",
            "Holds/intake",
            "Holds/intake/Held",
            "Holds/intake/Approved",
            "Holds/intake/Rejected",
            "Holds/inspections",
            "Holds/inspections/Held",
            "Holds/inspections/Approved",
            "Holds/inspections/Rejected",
        ]
    }
    # Nothing in anyone's own mailbox: every create was in the hold owner's.
    assert {entry[1] for entry in server.log if entry[0] == "create"} == {"holds@contoso.test"}
    approver = "approver@contoso.test"
    # Nothing on the folder every agent shares (Stalwart allows 10 grants on one folder); "l" on
    # each agent's own root, so the queue's ACL decides a CREATE or RENAME in it.
    assert server.acls.get("Holds", {}) == {}
    assert server.acls["Holds/intake"] == {"intake@agents.contoso.test": "l", approver: "l"}
    assert "inspections@agents.contoso.test" not in server.acls["Holds/intake"]
    # The approver has what Dovecot's has: move out of Held, into Approved or Rejected.
    assert server.acls["Holds/intake/Held"] == {
        "intake@agents.contoso.test": "lr",
        approver: "elrstw",
    }
    for name in ("Approved", "Rejected"):
        assert server.acls[f"Holds/intake/{name}"] == {
            "intake@agents.contoso.test": "lr",
            approver: "ilrsw",
        }
    assert server.subscribed["ops@contoso.test"] == set(stalwart.SUBSCRIBED_FOLDERS)
    assert server.subscribed["intake@agents.contoso.test"] == set(
        stalwart.SUBSCRIBED_FOLDERS
    ) | _queue("intake")
    assert server.subscribed[approver] == set(stalwart.SUBSCRIBED_FOLDERS) | _queue(
        "intake"
    ) | _queue("inspections")
    assert "holds@contoso.test" not in server.subscribed
    logins = [entry for entry in server.log if entry[0] == "login"]
    assert all(entry[1].endswith("%gateway@contoso.test") for entry in logins)
    assert all(entry[2] == "dev-gateway" for entry in logins)
    assert len(logins) == len([entry for entry in server.log if entry[0] == "logout"])


def test_ensure_mailboxes_changes_nothing_twice_and_removes_grants_it_did_not_make() -> None:
    server = FakeStalwart()
    _ensure(server)
    first = len(server.log)
    assert _ensure(server) == {"holds@contoso.test": []}
    # Stalwart refuses a second SUBSCRIBE, so only what is missing is subscribed.
    assert not [entry for entry in server.log[first:] if entry[0] in {"create", "subscribe"}]
    server.acls["Holds/intake/Approved"]["ops@contoso.test"] = "eilrstw"
    server.acls["Holds/intake/Held"]["intake@agents.contoso.test"] = "eilrstw"
    # An older layout granted "l" on the shared parent to every agent; that goes too.
    server.acls["Holds"] = {"intake@agents.contoso.test": "l"}
    _ensure(server)
    assert ("deleteacl", "Holds/intake/Approved", "ops@contoso.test") in server.log
    assert server.acls["Holds"] == {}
    assert server.acls["Holds/intake/Approved"]["intake@agents.contoso.test"] == "lr"
    assert "ops@contoso.test" not in server.acls["Holds/intake/Approved"]
    assert server.acls["Holds/intake/Held"]["intake@agents.contoso.test"] == "lr"


def test_ensure_mailboxes_fails_loudly_and_still_logs_out() -> None:
    server = FakeStalwart(fail_create="Holds/intake/Held")
    with pytest.raises(RuntimeError, match="cannot create Holds/intake/Held"):
        _ensure(server)
    assert server.log[-1] == ("logout", "holds@contoso.test")
    with pytest.raises(RuntimeError, match=r"Holds/intake: ACL is"):
        _ensure(FakeStalwart(ignore_setacl=True))
    unsubscribable = QUEUE.format(agent="intake", name="Held")
    with pytest.raises(RuntimeError, match=f"not subscribed: {unsubscribable}"):
        _ensure(FakeStalwart(unsubscribable=unsubscribable))
    for reserved in ("approver@contoso.test", "holds@contoso.test"):
        with pytest.raises(ValueError, match="reserved"):
            _ensure(FakeStalwart(), [*USERS, reserved])


def test_acl_responses_parse_as_stalwart_writes_them() -> None:
    class Client:
        def getacl(self, folder: str) -> tuple[str, list[bytes]]:
            assert folder == '"Holds/intake/Held"'
            return "OK", [
                b'"Holds/intake/Held" "holds@contoso.test" rliteswkxpa '
                b'"intake@agents.contoso.test" rl "approver@contoso.test" tewsirl'
            ]

    assert stalwart._acl(Client(), "Holds/intake/Held") == {  # type: ignore[arg-type]
        "holds@contoso.test": "rliteswkxpa",
        "intake@agents.contoso.test": "rl",
        "approver@contoso.test": "tewsirl",
    }
    assert stalwart._astrings('a "b c" "d \\"e\\"" f') == ["a", "b c", 'd "e"', "f"]
    assert stalwart._quoted('Shared Folders/a"b') == '"Shared Folders/a\\"b"'


def test_listed_names_parse_quoted_and_bare_mailboxes() -> None:
    assert stalwart._listed_name(b'(\\Sent) "/" "Sent Items"') == "Sent Items"
    assert stalwart._listed_name(b'() "/" INBOX') == "INBOX"


def test_probes_report_closed_endpoints_and_wait_for_times_out() -> None:
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        port = unused.getsockname()[1]
    assert not stalwart.port_open(port)
    assert not stalwart.http_ok(f"http://127.0.0.1:{port}/healthz/ready")
    with pytest.raises(TimeoutError, match="nothing"):
        stalwart.wait_for(lambda: False, 0.3, "nothing")
    stalwart.wait_for(lambda: True, 0.1, "at once")


def test_plan_command_prints_the_plan(tmp_path, capsys) -> None:
    users = tmp_path / "dev-users"
    users.write_text(DEV_USERS, encoding="utf-8")
    code = stalwart.main(
        [
            "plan",
            "--domain=contoso.test",
            "--agent-domain=agents.contoso.test",
            "--hostname=mail.contoso.test",
            "--gateway-host=gateway-ct",
            "--gateway-ip=172.30.0.21",
            f"--dev-users={users}",
        ]
    )
    assert code == 0
    assert [json.loads(line) for line in capsys.readouterr().out.splitlines()] == _plan()


def test_provision_applies_settings_then_restarts_for_accounts_and_folders(
    tmp_path, monkeypatch
) -> None:
    users = tmp_path / "dev-users"
    users.write_text(DEV_USERS, encoding="utf-8")
    events: list[Any] = []

    class Server:
        def __init__(self, binary: str, config: str) -> None:
            events.append(("boot", binary, config))

        def __enter__(self) -> Server:
            return self

        def __exit__(self, *_exc: object) -> None:
            events.append(("stop",))

        def running(self) -> bool:
            return True

    plan_paths: list[str] = []

    def run(
        command: list[str],
        *,
        check: bool,
        env: dict[str, str],
        timeout: int,
        capture_output: bool,
        text: bool,
    ) -> None:
        assert timeout == stalwart.CLI_TIMEOUT
        assert capture_output and text  # raw CLI output must not reach bootstrap logs
        plan_paths.append(command[-1])
        with open(command[-1], encoding="utf-8") as stream:
            plan = [json.loads(line) for line in stream]
        events.append(("apply", [operation["object"] for operation in plan][-1]))
        assert check and env["STALWART_USER"] == "admin" and env["STALWART_PASSWORD"] == "pw"

    def mailboxes(_factory, site, accounts, login, password) -> dict[str, list[str]]:
        events.append(("mailboxes", site.hold_prefix, list(accounts), login(accounts[0]), password))
        return {}

    monkeypatch.setenv("STALWART_RECOVERY_ADMIN", "admin:pw")
    monkeypatch.setattr(stalwart, "PrivateServer", Server)
    monkeypatch.setattr(stalwart.subprocess, "run", run)
    monkeypatch.setattr(stalwart, "wait_for", lambda *_args: None)
    monkeypatch.setattr(stalwart, "ensure_mailboxes", mailboxes)
    arguments = argparse.Namespace(
        domain="contoso.test",
        agent_domain="agents.contoso.test",
        hostname="mail.contoso.test",
        gateway_host="gateway-ct",
        gateway_ip="172.30.0.21",
        dev_users=str(users),
        stalwart="/bin/stalwart",
        cli="/bin/cli",
        config="/etc/config.json",
        state_dir=str(tmp_path),
        hold_owner=None,
        hold_prefix="Holds/{agent}/",
    )
    assert stalwart.provision(arguments) == 0
    assert events == [
        ("boot", "/bin/stalwart", "/etc/config.json"),
        ("apply", "SieveSystemScript"),
        ("stop",),
        ("boot", "/bin/stalwart", "/etc/config.json"),
        ("apply", "Account"),
        (
            "mailboxes",
            "Holds/{agent}/",
            ["ops@contoso.test", "intake@agents.contoso.test"],
            "ops@contoso.test%gateway@contoso.test",
            "dev-gateway",
        ),
        ("stop",),
    ]
    # The plans (with the dev passwords) were temporary files, never on the shared volume.
    assert [Path(path).name for path in plan_paths] == [
        "amx-settings.ndjson",
        "amx-accounts.ndjson",
    ]
    assert not any(Path(path).exists() for path in plan_paths)
    assert {path.name for path in tmp_path.iterdir()} == {"dev-users", "amx-provisioned.sha256"}
    # Run again with the same plan: nothing boots (the mailhost may hold the datastore).
    events.clear()
    assert stalwart.provision(arguments) == 0
    assert events == []
    # Live up stops runtime first, then repairs drift even if the digest matches.
    arguments.reapply = True
    assert stalwart.provision(arguments) == 0
    assert ("apply", "Account") in events
    arguments.reapply = False
    events.clear()
    users.write_text(DEV_USERS + "ops2@contoso.test|dev-ops2\n", encoding="utf-8")
    assert stalwart.provision(arguments) == 0
    assert ("apply", "Account") in events
    # The hold layout is part of what was provisioned: changing it provisions again.
    events.clear()
    arguments.hold_prefix = "Queue/{agent}/"
    assert stalwart.provision(arguments) == 0
    assert ("apply", "Account") in events


def test_stalwart_limits_postfix_does_not_have_are_lifted() -> None:
    plan = _plan()
    throttles = _operation(plan, "MtaInboundThrottle")
    assert throttles["matchOn"] == ["description"]
    assert {entry["description"]: entry["enable"] for entry in throttles["value"].values()} == {
        "Sender IP throttle": False,
        "Sender address to recipient throttle": False,
    }
    (allowed,) = _operation(plan, "AllowedIp")["value"].values()
    assert allowed["address"] == "172.30.0.0/24"
    assert _operation(plan, "MtaStageData")["value"]["maxMessages"] == expression("1000")
    rcpt = _operation(plan, "MtaStageRcpt")["value"]
    assert rcpt["waitOnFail"] == expression("1s")
    assert rcpt["maxFailures"] == expression("20")
    ehlo = _operation(plan, "MtaStageEhlo")["value"]
    assert ehlo == {"require": expression("false"), "rejectNonFqdn": expression("false")}
    folders = _operation(plan, "Email")["value"]["defaultFolders"]
    assert folders["sent"]["name"] == holds.SENT_FOLDER


@pytest.mark.parametrize("timed_out", [False, True])
def test_a_failed_apply_stops_the_server_and_leaves_no_marker(
    tmp_path, monkeypatch, timed_out, capsys
) -> None:
    users = tmp_path / "dev-users"
    users.write_text(DEV_USERS, encoding="utf-8")
    stopped: list[bool] = []

    class Server:
        def __init__(self, *_args: str) -> None:
            pass

        def __enter__(self) -> Server:
            return self

        def __exit__(self, *_exc: object) -> None:
            stopped.append(True)

        def running(self) -> bool:
            return True

    def run(command: list[str], **_kwargs: Any) -> None:
        assert "--json" in command
        if timed_out:
            assert _kwargs["timeout"] == stalwart.CLI_TIMEOUT
            raise stalwart.subprocess.TimeoutExpired(command, _kwargs["timeout"])
        raise stalwart.subprocess.CalledProcessError(
            1,
            command,
            stderr="PRIVATE_AUTH_PAYLOAD",
            output=json.dumps(
                {
                    "op": "update",
                    "object": "Authentication",
                    "index": 0,
                    "status": "error",
                    "error": "error: invalidProperties | PRIVATE_AUTH_PAYLOAD | "
                    "Properties: /passwordMinLength",
                }
            ),
        )

    monkeypatch.setenv("STALWART_RECOVERY_ADMIN", "admin:pw")
    monkeypatch.setattr(stalwart, "PrivateServer", Server)
    monkeypatch.setattr(stalwart.subprocess, "run", run)
    monkeypatch.setattr(stalwart, "wait_for", lambda *_args: None)
    arguments = argparse.Namespace(
        domain="contoso.test",
        agent_domain="agents.contoso.test",
        hostname="mail.contoso.test",
        gateway_host="gateway-ct",
        gateway_ip="172.30.0.21",
        dev_users=str(users),
        stalwart="/bin/stalwart",
        cli="/bin/cli",
        config="/etc/config.json",
        state_dir=str(tmp_path),
        hold_owner=None,
        hold_prefix="Holds/{agent}/",
    )
    error = stalwart.subprocess.TimeoutExpired if timed_out else RuntimeError
    with pytest.raises(error):
        stalwart.provision(arguments)
    assert stopped == [True]
    assert not (tmp_path / "amx-provisioned.sha256").exists()
    output = capsys.readouterr().out
    assert "PRIVATE_AUTH_PAYLOAD" not in output
    if not timed_out:
        assert "operation=update object=Authentication index=0 status=error " in output
        assert "code=invalidProperties property=passwordMinLength" in output


def test_a_server_that_exits_is_reported_at_once(tmp_path) -> None:
    server = stalwart.PrivateServer("/bin/false", str(tmp_path / "config.json"))
    server.command = ["/bin/false"]
    with server:
        server.process.wait()  # type: ignore[union-attr]
        with pytest.raises(RuntimeError, match="datastore is locked"):
            server.running()


def test_the_provisioning_hash_covers_the_grants_and_subscriptions() -> None:
    layout = json.loads(stalwart.layout_text(SITE, USERS))
    assert layout["owner"] == "holds@contoso.test"
    assert layout["grants"]["Holds/intake/Held"] == {
        "intake@agents.contoso.test": "lr",
        "approver@contoso.test": "lrswte",
    }
    assert (
        QUEUE.format(agent="intake", name="Held")
        in layout["subscriptions"]["intake@agents.contoso.test"]
    )
    # Another agent, or other rights, is another hash (a rerun would otherwise skip the change).
    assert stalwart.layout_text(SITE, USERS[:2]) != stalwart.layout_text(SITE, USERS)


HASH = "$6$saltsalt$" + "a" * 86
GEN, OLD_GEN = "0123456789abcdef", "fedcba9876543210"
REGISTERED = (
    "# amx accounts\n"
    f"probe@agents.contoso.test:{{SHA512-CRYPT}}{HASH}:enabled:{GEN}\n"
    f"sleepy@agents.contoso.test:{{SHA512-CRYPT}}{HASH}:disabled:{GEN}\n"
    f"gone@agents.contoso.test:-:purge:{GEN}\n"
    f"reborn@agents.contoso.test:{{SHA512-CRYPT}}{HASH}:enabled:{GEN}\n"
    f"ops@contoso.test:{{SHA512-CRYPT}}{HASH}:enabled:{GEN}\n"
    f"intake@agents.contoso.test:{{SHA512-CRYPT}}{HASH}:enabled:{GEN}\n"
    f"bad@agents.contoso.test:plaintext:enabled:{GEN}\n"
    f"odd@agents.contoso.test:{{SHA512-CRYPT}}{HASH}:paused:{GEN}\n"
    f"old@agents.contoso.test:{{SHA512-CRYPT}}{HASH}:enabled\n"
    f"nogen@agents.contoso.test:{{SHA512-CRYPT}}{HASH}:enabled:XYZ\n"
)


def test_registered_accounts_are_agents_only_and_never_a_dev_users(capsys) -> None:
    accounts = stalwart.registered_accounts(REGISTERED, SITE, ["intake@agents.contoso.test"])
    assert accounts == [
        ("probe@agents.contoso.test", HASH, "enabled", GEN),
        ("sleepy@agents.contoso.test", HASH, "disabled", GEN),
        ("gone@agents.contoso.test", "-", "purge", GEN),
        ("reborn@agents.contoso.test", HASH, "enabled", GEN),
    ]
    skipped = capsys.readouterr().err
    for fragment in ("ops@contoso.test", "intake@", "bad@", "odd@", "a malformed", "nogen@"):
        assert fragment in skipped


def test_account_plan_upserts_the_plans_account_shape_and_disables_by_permission() -> None:
    accounts = stalwart.registered_accounts(REGISTERED, SITE, ["intake@agents.contoso.test"])
    domain, upsert = stalwart.account_plan(SITE, accounts)
    assert domain["value"] == {"domain-agents": {"name": "agents.contoso.test"}}
    assert upsert["matchOn"] == ["name", "domainId"]
    probe = upsert["value"]["account-probe-agents-contoso-test"]
    assert probe["credentials"] == {"0": {"@type": "Password", "secret": HASH}}
    assert probe["description"] == f"amx generation {GEN}"
    assert probe["permissions"]["disabledPermissions"] == {"authenticate": False}
    sleepy = upsert["value"]["account-sleepy-agents-contoso-test"]
    assert sleepy["permissions"]["disabledPermissions"] == {"authenticate": True}
    assert "account-gone-agents-contoso-test" not in upsert["value"]
    assert stalwart.account_plan(SITE, []) == []


def test_sync_deletes_purged_and_earlier_accounts_then_provisions(tmp_path, monkeypatch) -> None:
    (tmp_path / "dev-users").write_text(DEV_USERS, encoding="utf-8")
    (tmp_path / "agents.passwd").write_text(REGISTERED, encoding="utf-8")
    server = FakeStalwart()
    server.folders["holds@contoso.test"] = {
        "INBOX",
        "Holds",
        "Holds/gone",
        "Holds/gone/Held",
        "Holds/reborn",
        "Holds/reborn/Held",
    }
    calls: list[tuple[list[str], str | None]] = []
    existing = [
        {"id": "g", "emailAddress": "gone@agents.contoso.test", "description": None},
        # An earlier agent of the same name: another generation's account.
        {
            "id": "r",
            "emailAddress": "reborn@agents.contoso.test",
            "description": "amx generation " + OLD_GEN,
        },
        {
            "id": "p",
            "emailAddress": "probe@agents.contoso.test",
            "description": "amx generation " + GEN,
        },
    ]

    class Result:
        stdout = "".join(json.dumps(record) + "\n" for record in existing)

    def run(argv, **kwargs):
        calls.append((argv, kwargs.get("input")))
        assert kwargs["timeout"] == stalwart.CLI_TIMEOUT
        assert kwargs["env"]["STALWART_URL"] == "http://mailhost-ct:8080"
        return Result()

    monkeypatch.setattr(stalwart.subprocess, "run", run)
    monkeypatch.setattr(stalwart, "_imap_client", lambda _host, _port: server.client())
    monkeypatch.setenv("STALWART_RECOVERY_ADMIN", "admin:dev-admin")
    arguments = argparse.Namespace(
        domain="contoso.test",
        agent_domain="agents.contoso.test",
        hostname="mail.contoso.test",
        gateway_host="gateway-ct",
        gateway_ip="172.30.0.21",
        hold_owner=None,
        hold_prefix=stalwart.HOLD_PREFIX,
        dev_users=str(tmp_path / "dev-users"),
        accounts=str(tmp_path / "agents.passwd"),
        url="http://mailhost-ct:8080",
        imap_host="mailhost-ct",
        imap_port=143,
        cli="stalwart-cli",
        watch=False,
    )
    assert stalwart.sync(arguments) == 0
    query, delete, apply = calls
    assert query[0][2:4] == ["query", "Account"]
    assert delete[0][2:] == ["delete", "Account", "--ids", "g,r"]  # probe's is current
    assert apply[0][:3] == ["stalwart-cli", "--no-color", "apply"]
    assert "reborn" in (apply[1] or "") and "plaintext" not in (apply[1] or "")
    for folder in ("Holds/gone/Held", "Holds/gone", "Holds/reborn/Held"):
        assert ("delete", "holds@contoso.test", folder) in server.log
    # The enabled agents get their queues again; the disabled one is left as it is.
    assert "Holds/probe/Held" in server.folders["holds@contoso.test"]
    assert "Holds/reborn/Held" in server.folders["holds@contoso.test"]
    assert "Holds/sleepy/Held" not in server.folders["holds@contoso.test"]


def test_compose_gives_the_sync_service_the_init_containers_layout() -> None:
    text = (ROOT / "deploy" / "compose.stalwart.yaml").read_text(encoding="utf-8")
    services = yaml.load(text, Loader=_ComposeLoader)["services"]

    def arguments(service: str) -> dict[str, str]:
        return dict(
            item.removeprefix("--").partition("=")[::2] for item in services[service]["command"]
        )

    init, sync = arguments("stalwart-init-ct"), arguments("stalwart-sync-ct")
    for key in ("domain", "agent-domain", "hold-owner", "hold-prefix", "dev-users"):
        assert sync[key] == init[key]
    assert "watch" in sync


@pytest.mark.parametrize("final_state", ["disabled", "purge"])
@pytest.mark.parametrize("revert", [False, True])
def test_watch_applies_sampled_bytes_despite_change_and_reversion(
    tmp_path, monkeypatch, capsys, final_state, revert
):
    import hashlib

    users = tmp_path / "dev-users"
    users.write_text(DEV_USERS)
    path = tmp_path / "accounts"
    final = f"probe@agents.contoso.test:{{SHA512-CRYPT}}{HASH}:{final_state}:{GEN}\n"
    intermediate = final.replace(final_state, "enabled")
    path.write_text(final if revert else intermediate)
    arguments = argparse.Namespace(
        **dataclasses.asdict(SITE),
        dev_users=str(users),
        accounts=str(path),
        url="http://fixture.invalid",
        imap_host="fixture.invalid",
        imap_port=143,
        cli="fixture-cli",
        watch=True,
    )
    server = FakeStalwart()
    server.folders["holds@contoso.test"] = {"INBOX", "Holds/probe", "Holds/probe/Held"}
    original_inputs = stalwart.provisioning_inputs
    inputs = []

    def provisioning_inputs(*args):
        inputs.append(True)
        if revert and len(inputs) == 1:
            # Between watcher's sample/hash and sync's old second read: A -> B.
            path.write_text(intermediate)
        return original_inputs(*args)

    applied = []

    def run(argv, **kwargs):
        assert kwargs["timeout"] == stalwart.CLI_TIMEOUT
        if "query" in argv:
            return argparse.Namespace(
                stdout=json.dumps(
                    {
                        "id": "p",
                        "emailAddress": "probe@agents.contoso.test",
                        "description": stalwart.generation_note(GEN),
                    }
                )
            )
        if "delete" in argv:
            applied.append("purge")
        else:
            account = json.loads(kwargs["input"].splitlines()[-1])["value"]
            disabled = account["account-probe-agents-contoso-test"]["permissions"]
            applied.append(
                "disabled" if disabled["disabledPermissions"]["authenticate"] else "enabled"
            )
        # B -> A during application defeats even a pre/post path-hash comparison.
        path.write_text(final)
        return argparse.Namespace(stdout="")

    class StopWatch(BaseException):
        pass

    ticks = []

    def tick(seconds):
        assert seconds == 1
        ticks.append(True)
        if len(ticks) == 2:
            raise StopWatch

    monkeypatch.setenv("STALWART_RECOVERY_ADMIN", "admin:fixture")
    monkeypatch.setattr(stalwart, "provisioning_inputs", provisioning_inputs)
    monkeypatch.setattr(stalwart, "_imap_client", lambda *_: server.client())
    monkeypatch.setattr(stalwart.subprocess, "run", run)
    monkeypatch.setattr(stalwart.time, "sleep", tick)
    with pytest.raises(StopWatch):
        stalwart.sync(arguments)
    assert applied == ([final_state] if revert else ["enabled", final_state])
    assert hashlib.sha256(final.encode()).hexdigest()[:12] in capsys.readouterr().out
    if final_state == "purge":
        assert "Holds/probe/Held" not in server.folders["holds@contoso.test"]
