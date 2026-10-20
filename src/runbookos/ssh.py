from __future__ import annotations

import os
import selectors
import shutil
import signal
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .errors import ConfigurationError, ExecutionUnknown
from .models import Host, SSHProfile
from .remote import command as remote_command

MAX_STDOUT_BYTES = 256 * 1024
MAX_STDERR_BYTES = 16 * 1024
MAX_RESPONSE_DEPTH = 32
MAX_RESPONSE_NODES = 10_000
MAX_RESPONSE_STRING_BYTES = 64 * 1024
_TERM_GRACE_SECONDS = 0.5


def _validate_response_tree(value: object) -> None:
    nodes = 0
    pending: list[tuple[object, int]] = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > MAX_RESPONSE_NODES or depth > MAX_RESPONSE_DEPTH:
            raise ValueError("remote response structure exceeds limits")
        if isinstance(item, str):
            if len(item.encode("utf-8")) > MAX_RESPONSE_STRING_BYTES:
                raise ValueError("remote response string exceeds limit")
        elif isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key.encode("utf-8")) > 1024:
                    raise ValueError("remote response has an invalid key")
                pending.append((child, depth + 1))
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif item is not None and type(item) not in {bool, int, float}:
            raise ValueError("remote response contains an unsupported value")


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    """Stop ssh and descendants, then reap the leader within a bounded interval."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=_TERM_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=_TERM_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            pass


def _bounded_communicate(
    argv: list[str], env: dict[str, str], timeout: float
) -> tuple[int, bytes, bytes, bool, bool]:
    """Collect bounded output while the child runs; never buffer unbounded pipes."""
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
        close_fds=True,
    )
    assert process.stdout is not None and process.stderr is not None
    limits = {process.stdout: MAX_STDOUT_BYTES, process.stderr: MAX_STDERR_BYTES}
    captured = {process.stdout: bytearray(), process.stderr: bytearray()}
    selector = selectors.DefaultSelector()
    for stream in limits:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    timed_out = overflow = False
    try:
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            events = selector.select(min(remaining, 0.1)) if selector.get_map() else []
            if not selector.get_map() and process.poll() is None:
                time.sleep(min(remaining, 0.05))
            for key, _ in events:
                stream = key.fileobj
                room = limits[stream] - len(captured[stream])
                try:
                    chunk = os.read(stream.fileno(), min(65536, room + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                if len(chunk) > room:
                    overflow = True
                    break
                captured[stream].extend(chunk)
            if overflow:
                break
        if timed_out or overflow:
            _terminate_process_group(process)
            # Close pipes after termination; remaining output is deliberately discarded.
            for stream in (process.stdout, process.stderr):
                try:
                    stream.close()
                except OSError:
                    pass
        else:
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return (
            process.returncode if process.returncode is not None else -signal.SIGKILL,
            bytes(captured[process.stdout]),
            bytes(captured[process.stderr]),
            timed_out,
            overflow,
        )
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
        if process.poll() is None:
            _terminate_process_group(process)


@dataclass(frozen=True)
class SSHResult:
    ok: bool
    data: dict
    error: str | None = None
    uncertain: bool = False
    duration_seconds: float = 0.0


class SSHAdapter:
    """OpenSSH adapter with pinned host keys and no retries or shell input."""

    def __init__(self, profiles: dict[str, SSHProfile], ssh_binary: str = "ssh") -> None:
        found = shutil.which(ssh_binary)
        if not found:
            raise ConfigurationError(f"OpenSSH client not found: {ssh_binary}")
        self.ssh_binary = found
        self.profiles = profiles

    @staticmethod
    def _validate_files(profile: SSHProfile, host: Host) -> tuple[str, Path]:
        identity = Path(profile.identity_file)
        known_hosts = Path(profile.known_hosts_file)
        if not identity.is_file():
            raise ConfigurationError(f"SSH identity file does not exist: {identity}")
        mode = stat.S_IMODE(identity.stat().st_mode)
        if mode & 0o077:
            raise ConfigurationError(
                f"SSH identity must not be accessible by group/other: {identity}"
            )
        try:
            if stat.S_ISLNK(known_hosts.lstat().st_mode):
                raise ConfigurationError(f"pinned known_hosts must not be a symlink: {known_hosts}")
            trusted_known_hosts = known_hosts.resolve(strict=True)
            fd = os.open(
                trusted_known_hosts,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
        except (OSError, ValueError) as exc:
            raise ConfigurationError(
                f"cannot safely open pinned known_hosts file: {known_hosts}"
            ) from exc
        try:
            metadata = os.fstat(fd)
            mode = stat.S_IMODE(metadata.st_mode)
            if not stat.S_ISREG(metadata.st_mode):
                raise ConfigurationError(
                    f"pinned known_hosts must be a regular file: {known_hosts}"
                )
            if metadata.st_uid not in {os.geteuid(), 0}:
                raise ConfigurationError(
                    f"pinned known_hosts must be owned by current user or root: {known_hosts}"
                )
            if mode & 0o022:
                raise ConfigurationError(
                    f"pinned known_hosts must not be group/other writable: {known_hosts}"
                )
            if metadata.st_size == 0:
                raise ConfigurationError(
                    f"pinned known_hosts file is missing or empty: {known_hosts}"
                )
        finally:
            os.close(fd)
        alias = host.host_key_alias or host.address
        check = subprocess.run(
            ["ssh-keygen", "-F", alias, "-f", str(trusted_known_hosts)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            env={"PATH": os.defpath, "LC_ALL": "C"},
        )
        if check.returncode != 0:
            raise ConfigurationError(
                f"no pinned host key for {alias!r} in {known_hosts}; refusing SSH"
            )
        return alias, trusted_known_hosts

    def execute(self, host: Host, action: str, arguments: dict, timeout_seconds: int) -> SSHResult:
        try:
            profile = self.profiles[host.ssh_profile]
        except KeyError as exc:
            raise ConfigurationError(f"SSH profile {host.ssh_profile!r} is not configured") from exc
        alias, trusted_known_hosts = self._validate_files(profile, host)
        options = [
            "-T",
            "-F",
            "/dev/null",
            "-p",
            str(host.port),
            "-oBatchMode=yes",
            "-oPreferredAuthentications=publickey",
            "-oPasswordAuthentication=no",
            "-oKbdInteractiveAuthentication=no",
            "-oStrictHostKeyChecking=yes",
            "-oGlobalKnownHostsFile=/dev/null",
            "-oUpdateHostKeys=no",
            "-oIdentitiesOnly=yes",
            "-oIdentityAgent=none",
            "-oForwardAgent=no",
            "-oClearAllForwardings=yes",
            "-oPermitLocalCommand=no",
            "-oProxyCommand=none",
            "-oProxyJump=none",
            "-oCanonicalizeHostname=no",
            "-oRequestTTY=no",
            "-oLogLevel=ERROR",
            f"-oConnectTimeout={profile.connect_timeout_seconds}",
            f"-oServerAliveInterval={profile.server_alive_interval_seconds}",
            "-oServerAliveCountMax=1",
            f"-oUserKnownHostsFile={trusted_known_hosts}",
            f"-oHostKeyAlias={alias}",
            "-i",
            profile.identity_file,
        ]
        remote = remote_command(
            {"action": action, "arguments": arguments, "timeout_seconds": timeout_seconds}
        )
        argv = [self.ssh_binary, *options, f"{host.user}@{host.address}", remote]
        env = {"PATH": os.defpath, "LC_ALL": "C", "LANG": "C"}
        start = time.monotonic()
        try:
            returncode, stdout, stderr, timed_out, overflow = _bounded_communicate(
                argv,
                env,
                timeout_seconds
                + profile.connect_timeout_seconds
                + profile.server_alive_interval_seconds
                + 2,
            )
        except OSError as exc:
            raise ExecutionUnknown(
                "SSH client could not be started; no retry was attempted"
            ) from exc
        elapsed = time.monotonic() - start
        if timed_out:
            raise ExecutionUnknown(
                "SSH client timeout; remote outcome is unknown; no retry was attempted"
            )
        if overflow:
            raise ExecutionUnknown(
                "SSH output limit exceeded; remote outcome is unknown; no retry was attempted"
            )
        if returncode != 0:
            detail = (stderr or stdout).decode("utf-8", errors="replace").strip()[:1000]
            raise ExecutionUnknown(
                f"SSH exited {returncode}; remote outcome is unknown; no retry was attempted: {detail}"
            )
        try:
            import json

            response = json.loads(stdout)
            if (
                not isinstance(response, dict)
                or not set(response) <= {"ok", "data", "error", "uncertain"}
                or not {"ok", "data"} <= set(response)
                or type(response.get("ok")) is not bool
                or not isinstance(response.get("data"), dict)
                or (
                    "error" in response
                    and response.get("error") is not None
                    and not isinstance(response.get("error"), str)
                )
                or ("uncertain" in response and type(response.get("uncertain")) is not bool)
            ):
                raise ValueError("invalid remote result shape")
            _validate_response_tree(response)
        except (ValueError, TypeError, RecursionError, UnicodeDecodeError) as exc:
            raise ExecutionUnknown(
                "remote response was missing or invalid; remote outcome is unknown"
            ) from exc
        return SSHResult(
            ok=response.get("ok") is True,
            data=response["data"],
            error=response.get("error"),
            uncertain=response.get("uncertain") is True,
            duration_seconds=round(elapsed, 3),
        )
