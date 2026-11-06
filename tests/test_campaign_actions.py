from __future__ import annotations

import pytest

from runbookos.actions import REGISTRY, validate_action
from runbookos.errors import ConfigurationError
from runbookos.remote import REMOTE_SOURCE


@pytest.mark.parametrize(
    ("action_id", "arguments"),
    [
        ("systemd.start", {"unit": "runbookos-campaign-b04-app.service"}),
        ("config.restore_fixture", {"fixture_id": "app_config"}),
        ("config.restore_fixture", {"fixture_id": "proxy_config"}),
        ("dns.restore_fixture", {"fixture_id": "resolver_config"}),
        ("network.restore_fixture", {"fixture_id": "isolated_link"}),
        ("storage.release_fixture", {"fixture_id": "bounded_volume"}),
        ("resource.restore_fixture", {"fixture_id": "worker_quota"}),
        ("dependency.restore_fixture", {"fixture_id": "backend_service"}),
        ("application.recover_worker", {"fixture_id": "worker_service"}),
        ("postgresql.start_fixture", {"cluster": "16-b04"}),
        ("dns.resolve_fixture", {"fixture_id": "b04_resolver"}),
    ],
)
def test_b04_actions_have_bounded_registered_arguments(action_id, arguments):
    action = validate_action(action_id, arguments)
    assert action.max_timeout_seconds <= 60
    assert action.risk in ({"low"} if action_id == "dns.resolve_fixture" else {"medium", "high"})
    assert action.read_only is (action_id == "dns.resolve_fixture")


@pytest.mark.parametrize(
    ("action_id", "arguments"),
    [
        ("config.restore_fixture", {"fixture_id": "../../etc/shadow"}),
        ("dns.restore_fixture", {"fixture_id": "main_resolver"}),
        ("network.restore_fixture", {"fixture_id": "net-01"}),
        ("storage.release_fixture", {"fixture_id": "/"}),
        ("resource.restore_fixture", {"fixture_id": "host"}),
        ("dependency.restore_fixture", {"fixture_id": "primary_database"}),
        ("application.recover_worker", {"fixture_id": "system"}),
        ("postgresql.start_fixture", {"cluster": "16-main"}),
        ("dns.resolve_fixture", {"fixture_id": "net-01"}),
        ("systemd.start", {"unit": "arbitrary.service; touch /tmp/pwned"}),
        ("systemd.start", {"unit": "runbookos-campaign-b04-app.service", "command": "id"}),
    ],
)
def test_b04_actions_reject_out_of_scope_or_command_shaped_arguments(action_id, arguments):
    with pytest.raises(ConfigurationError):
        validate_action(action_id, arguments)


def test_b04_action_dispatch_has_only_fixed_fixture_helper_operations():
    for action_id in (
        "config.restore_fixture",
        "dns.restore_fixture",
        "network.restore_fixture",
        "storage.release_fixture",
        "resource.restore_fixture",
        "dependency.restore_fixture",
        "application.recover_worker",
        "postgresql.start_fixture",
    ):
        assert action_id in REMOTE_SOURCE
    assert "/usr/local/sbin/runbookos-campaign-b04-recover" in REMOTE_SOURCE
    assert "restore-config" in REMOTE_SOURCE
    assert "release-storage" in REMOTE_SOURCE
    assert "restore-network" in REMOTE_SOURCE
    assert "systemd.start" in REMOTE_SOURCE
    assert "dns.resolve_fixture" in REMOTE_SOURCE
    assert all(
        not REGISTRY[action].read_only for action in REGISTRY if action.endswith("restore_fixture")
    )


def test_fixture_inspection_exposes_validity_and_never_unrecognized_http_body(monkeypatch, capsys):
    import builtins
    import http.client
    import io
    import json
    import os
    from types import SimpleNamespace

    from test_probes import run_remote_request

    original_open = builtins.open
    original_stat = os.stat

    def fixture_open(path, *args, **kwargs):
        if str(path).startswith("/var/lib/runbookos-campaign-b04/config/"):
            if str(path).endswith("/app.json"):
                return io.StringIO('{"backend_host":"backend.b04.test","backend_port":18911}')
            return io.StringIO('{"unexpected":true}')
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fixture_open)
    monkeypatch.setattr(
        os,
        "stat",
        lambda path, *a, **k: (
            SimpleNamespace(st_size=20)
            if str(path).startswith("/var/lib/runbookos-campaign-b04/config/")
            else original_stat(path, *a, **k)
        ),
    )
    monkeypatch.setattr(os.path, "islink", lambda path: False)

    class HTTP:
        status = 503
        timeouts = []

        def __init__(self, *a, **k):
            self.timeouts.append(k["timeout"])

        def request(self, *a, **k):
            pass

        def getresponse(self):
            return self

        def read(self, size):
            assert size == 64
            return b"private-unrecognized-health-content"

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPConnection", HTTP)
    output = run_remote_request(
        monkeypatch, capsys, "application.inspect_fixture", {"fixture_id": "web_stack"}, 1
    )
    assert output["ok"] is True
    assert output["data"]["observations"]["app"]["configuration_valid"] is True
    assert output["data"]["observations"]["proxy"]["configuration_valid"] is False
    assert "private-unrecognized" not in json.dumps(output)
    assert output["data"]["observations"]["app"]["health_code"] == "unrecognized-response"
    assert HTTP.timeouts == [0.5, 0.5]
    run_remote_request(
        monkeypatch, capsys, "application.inspect_fixture", {"fixture_id": "web_stack"}, 4
    )
    assert HTTP.timeouts[-2:] == [2, 2]
    assert REGISTRY["application.inspect_fixture"].max_timeout_seconds == 4


@pytest.mark.parametrize(
    ("action", "args"),
    [
        ("application.inspect_fixture", {"fixture_id": "other_stack"}),
        ("resource.inspect_fixture", {"fixture_id": "host"}),
    ],
)
def test_fixture_observations_cannot_select_arbitrary_resources(action, args):
    with pytest.raises(ConfigurationError):
        validate_action(action, args)
