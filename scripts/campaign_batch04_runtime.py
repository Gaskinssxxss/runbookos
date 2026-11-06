"""Identity-checked lifecycle for the acceptance-owned Batch 04 Qwen process."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import subprocess
import time
from pathlib import Path

import campaign_batch03_live as b03

RUNTIME = Path("/home/morphious/.local/src/llama.cpp/build/bin/llama-server")
MODEL = Path("/home/morphious/models/llama.cpp/qwen3.5-9b-instruct-q5_k_m.gguf")
KEY = Path("/home/morphious/.config/runbookos/llama-api-key")
IDENTITY = b03.LOCAL / "runtime/server-identity.json"


def start_ticks(pid: int) -> str:
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("start", "stop"))
    args = parser.parse_args()
    if args.operation == "stop":
        record = json.loads(IDENTITY.read_text())
        pid = record["pid"]
        if Path(os.readlink(f"/proc/{pid}/exe")).resolve() != RUNTIME.resolve():
            raise SystemExit("owned process executable mismatch")
        if record.get("start_ticks") and start_ticks(pid) != record["start_ticks"]:
            raise SystemExit("owned process start identity mismatch")
        if b"--api-key-file" not in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0"):
            raise SystemExit("owned server arguments mismatch")
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and Path(f"/proc/{pid}/exe").exists():
            time.sleep(0.1)
        if Path(f"/proc/{pid}/exe").exists():
            raise SystemExit("owned server did not terminate")
        print("OWNED_SERVER_STOPPED")
        return
    with socket.socket() as sock:
        if sock.connect_ex(("127.0.0.1", 18080)) == 0:
            raise SystemExit("port occupied; refusing interference")
    available = (
        int(
            next(
                line.split()[1]
                for line in Path("/proc/meminfo").read_text().splitlines()
                if line.startswith("MemAvailable:")
            )
        )
        * 1024
    )
    if available < 16 * 1024**3:
        raise SystemExit("prelaunch memory below 16 GiB")
    if KEY.stat().st_mode & 0o077:
        raise SystemExit("provider key not owner-only")
    for path, expected in (
        (RUNTIME, "98a8581124ccf8ba775a89e1899c895b2d4a2053b9830f8b044fe69b928c02ac"),
        (MODEL, "dc2a39aef291f91a9116ad214058da0d86eb648743a124bd8c333787c4b9c91c"),
    ):
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
                raise SystemExit("runtime/model mismatch")
    log = IDENTITY.parent / ("llama-server-b04-" + str(time.time_ns()) + ".log")
    fd = os.open(log, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        proc = subprocess.Popen(
            [
                str(RUNTIME),
                "--model",
                str(MODEL),
                "--host",
                "127.0.0.1",
                "--port",
                "18080",
                "--alias",
                "qwen3.5-9b-instruct",
                "--ctx-size",
                "8192",
                "--parallel",
                "1",
                "--cache-ram",
                "512",
                "--threads",
                "4",
                "--threads-batch",
                "4",
                "--timeout",
                "130",
                "--reasoning",
                "off",
                "--reasoning-format",
                "none",
                "--reasoning-budget",
                "0",
                "--api-key-file",
                str(KEY),
                "--no-webui",
            ],
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    record = {
        "pid": proc.pid,
        "start_ticks": start_ticks(proc.pid),
        "prelaunch_memavailable_bytes": available,
        "executable": str(RUNTIME),
    }
    IDENTITY.with_name("server-identity-before-" + str(time.time_ns()) + ".json").write_bytes(
        IDENTITY.read_bytes()
    )
    fd = os.open(IDENTITY, os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(record, stream)
    print(json.dumps(record))


if __name__ == "__main__":
    main()
