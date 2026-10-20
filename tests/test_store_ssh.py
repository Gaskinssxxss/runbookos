from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from runbookos.errors import ConfigurationError, ExecutionUnknown
from runbookos.models import Host, SSHProfile
from runbookos.remote import command as remote_command
from runbookos.ssh import SSHAdapter
from runbookos.store import SQLiteStore


def test_remote_dispatcher_decodes_base64_payload() -> None:
    command = remote_command({"action": "os.uptime", "arguments": {}, "timeout_seconds": 3})
    result = subprocess.run(shlex.split(command), capture_output=True, text=True, timeout=5)
    response = json.loads(result.stdout)
    assert result.returncode == 0
    assert response["ok"] is True
    assert response["data"]["seconds"] > 0


def test_sqlite_permissions_and_audit_chain(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "private/state.sqlite3")
    assert (tmp_path / "private/state.sqlite3").stat().st_mode & 0o777 == 0o600
    store.create_plan(
        {
            "plan_id": "p1",
            "plan_hash": "h1",
            "created_at": "now",
            "status": "ready",
        }
    )
    store.start_execution("e1", "p1", "start")
    store.finish_execution("e1", "succeeded", "end", {"result": "ok"})
    assert store.verify_audit_chain() == (True, 3)
    import sqlite3

    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE audit_events SET payload_json='{}' WHERE sequence=1")
    assert store.verify_audit_chain()[0] is False


def _fake_ssh(tmp_path: Path, payload: str, *, exit_code: int = 0) -> tuple[Path, Path]:
    return _fake_ssh_source(
        tmp_path,
        f"print({payload!r})\nraise SystemExit({exit_code})\n",
    )


def _fake_ssh_source(tmp_path: Path, source: str) -> tuple[Path, Path]:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    capture = tmp_path / "ssh-argv.json"
    fake = bindir / "ssh-fixture"
    fake.write_text(
        "#!/usr/bin/python3\n"
        "import json,sys\n"
        f"open({str(capture)!r},'w').write(json.dumps(sys.argv[1:]))\n" + source
    )
    fake.chmod(0o700)
    return fake, capture


def test_ssh_uses_pinned_host_key_and_fixed_protocol(
    tmp_path: Path, key_material, monkeypatch
) -> None:
    private, known_hosts = key_material
    result_json = json.dumps(
        {
            "ok": True,
            "data": {"unit": "nginx.service", "active": True},
            "error": None,
            "uncertain": False,
        }
    )
    fake, capture = _fake_ssh(tmp_path, result_json)
    adapter = SSHAdapter(
        {
            "test": SSHProfile(
                identity_file=str(private),
                known_hosts_file=str(known_hosts),
                connect_timeout_seconds=1,
                server_alive_interval_seconds=1,
            )
        },
        str(fake),
    )
    host = Host(
        address="127.0.0.1",
        user="runner",
        role="web-server",
        ssh_profile="test",
        host_key_alias="runbookos-test-web",
    )
    result = adapter.execute(host, "systemd.is_active", {"unit": "nginx.service"}, 3)
    argv = json.loads(capture.read_text())
    assert result.ok and result.data["active"] is True
    assert "-oStrictHostKeyChecking=yes" in argv
    assert "-oGlobalKnownHostsFile=/dev/null" in argv
    assert "-oForwardAgent=no" in argv
    remote = argv[-1]
    assert "systemd.is_active" not in remote
    assert "nginx.service" not in remote
    assert "-oProxyCommand=none" in argv


def test_ssh_nonzero_is_unknown_without_retry(tmp_path: Path, key_material) -> None:
    private, known_hosts = key_material
    fake, capture = _fake_ssh(tmp_path, "", exit_code=255)
    adapter = SSHAdapter(
        {
            "test": SSHProfile(
                identity_file=str(private),
                known_hosts_file=str(known_hosts),
                connect_timeout_seconds=1,
                server_alive_interval_seconds=1,
            )
        },
        str(fake),
    )
    host = Host(
        address="127.0.0.1",
        user="runner",
        role="web-server",
        ssh_profile="test",
        host_key_alias="runbookos-test-web",
    )
    with pytest.raises(ExecutionUnknown, match="no retry"):
        adapter.execute(host, "systemd.is_active", {"unit": "nginx.service"}, 3)
    assert capture.exists()
    assert len(json.loads(capture.read_text())) > 0


def test_ssh_requires_pinned_host_key(tmp_path: Path, key_material) -> None:
    private, known_hosts = key_material
    fake, _ = _fake_ssh(tmp_path, '{"ok":true,"data":{}}')
    adapter = SSHAdapter(
        {
            "test": SSHProfile(
                identity_file=str(private),
                known_hosts_file=str(known_hosts),
                connect_timeout_seconds=1,
                server_alive_interval_seconds=1,
            )
        },
        str(fake),
    )
    host = Host(
        address="127.0.0.1",
        user="runner",
        role="web-server",
        ssh_profile="test",
        host_key_alias="untrusted-host",
    )
    with pytest.raises(ConfigurationError, match="no pinned host key"):
        adapter.execute(host, "systemd.is_active", {"unit": "nginx.service"}, 3)


def _adapter_and_host(tmp_path: Path, private: Path, known_hosts: Path, fake: Path):
    adapter = SSHAdapter(
        {
            "test": SSHProfile(
                identity_file=str(private),
                known_hosts_file=str(known_hosts),
                connect_timeout_seconds=1,
                server_alive_interval_seconds=1,
            )
        },
        str(fake),
    )
    host = Host(
        address="127.0.0.1",
        user="runner",
        role="web-server",
        ssh_profile="test",
        host_key_alias="runbookos-test-web",
    )
    return adapter, host


def test_ssh_timeout_is_unknown_and_process_is_terminated(tmp_path: Path, key_material) -> None:
    private, known_hosts = key_material
    pid_file = tmp_path / "child.pid"
    fake, _ = _fake_ssh_source(
        tmp_path,
        f"import os,time\nopen({str(pid_file)!r},'w').write(str(os.getpid()))\ntime.sleep(30)\n",
    )
    adapter, host = _adapter_and_host(tmp_path, private, known_hosts, fake)
    with pytest.raises(ExecutionUnknown, match="no retry"):
        adapter.execute(host, "systemd.is_active", {"unit": "nginx.service"}, 1)
    pid = int(pid_file.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_ssh_oversized_output_is_bounded_and_unknown(
    tmp_path: Path, key_material, stream: str
) -> None:
    private, known_hosts = key_material
    pid_file = tmp_path / "overflow.pid"
    fake, _ = _fake_ssh_source(
        tmp_path,
        f"import os,sys\nopen({str(pid_file)!r},'w').write(str(os.getpid()))\n"
        f"while True:\n sys.{stream}.write('x'*8192)\n sys.{stream}.flush()\n",
    )
    adapter, host = _adapter_and_host(tmp_path, private, known_hosts, fake)
    with pytest.raises(ExecutionUnknown, match="output limit exceeded"):
        adapter.execute(host, "systemd.is_active", {"unit": "nginx.service"}, 3)
    with pytest.raises(ProcessLookupError):
        os.kill(int(pid_file.read_text()), 0)


@pytest.mark.parametrize("payload", ["{not-json", '{"ok":true'])
def test_ssh_malformed_or_partial_response_is_unknown(tmp_path: Path, key_material, payload: str):
    private, known_hosts = key_material
    fake, _ = _fake_ssh(tmp_path, payload)
    adapter, host = _adapter_and_host(tmp_path, private, known_hosts, fake)
    with pytest.raises(ExecutionUnknown, match="invalid"):
        adapter.execute(host, "systemd.is_active", {"unit": "nginx.service"}, 3)


def test_known_hosts_permissions_and_symlinks(tmp_path: Path, key_material):
    private, known_hosts = key_material
    fake, _ = _fake_ssh(tmp_path, '{"ok":true,"data":{}}')
    adapter, host = _adapter_and_host(tmp_path, private, known_hosts, fake)
    known_hosts.chmod(0o644)
    assert adapter.execute(host, "systemd.is_active", {"unit": "nginx.service"}, 3).ok
    known_hosts.chmod(0o622)
    with pytest.raises(ConfigurationError, match="not.*writable"):
        adapter.execute(host, "systemd.is_active", {"unit": "nginx.service"}, 3)
    known_hosts.chmod(0o600)
    linked = tmp_path / "known_hosts_link"
    linked.symlink_to(known_hosts)
    unsafe, unsafe_host = _adapter_and_host(tmp_path, private, linked, fake)
    with pytest.raises(ConfigurationError, match="symlink"):
        unsafe.execute(unsafe_host, "systemd.is_active", {"unit": "nginx.service"}, 3)


def test_known_hosts_rejects_untrusted_owner(tmp_path: Path, key_material, monkeypatch):
    private, known_hosts = key_material
    fake, _ = _fake_ssh(tmp_path, '{"ok":true,"data":{}}')
    adapter, host = _adapter_and_host(tmp_path, private, known_hosts, fake)
    monkeypatch.setattr(
        "runbookos.ssh.os.fstat",
        lambda _fd: SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_uid=os.geteuid() + 1,
            st_size=128,
        ),
    )
    with pytest.raises(ConfigurationError, match="owned by current user or root"):
        adapter.execute(host, "systemd.is_active", {"unit": "nginx.service"}, 3)
