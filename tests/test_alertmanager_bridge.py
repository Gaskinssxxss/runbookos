from __future__ import annotations

import base64
import threading
import urllib.error
import urllib.request

import pytest

from runbookos.adapters.alertmanager_bridge import MAX_BODY, create_server


def test_bridge_rejects_non_loopback_and_missing_credentials():
    with pytest.raises(ValueError, match="loopback"):
        create_server(
            host="0.0.0.0",
            upstream_user="u",
            upstream_password="p" * 24,
            key_id="k1",
            signing_secret="s" * 32,
        )
    with pytest.raises(ValueError, match="credentials"):
        create_server(upstream_user="", upstream_password="", key_id="k1", signing_secret="s" * 32)


def test_bridge_fails_closed_when_downstream_unavailable():
    server = create_server(
        port=0,
        downstream_port=65500,
        upstream_user="sender",
        upstream_password="p" * 32,
        key_id="am-v1",
        signing_secret="s" * 32,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_address[1]}/api/v2/alerts",
            data=b"{}",
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": "Basic " + base64.b64encode(b"sender:" + b"p" * 32).decode(),
            },
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request, timeout=2)
        assert error.value.code == 502
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_bridge_rejects_oversized_and_unauthenticated_requests():
    server = create_server(
        port=0,
        downstream_port=8765,
        upstream_user="sender",
        upstream_password="p" * 32,
        key_id="am-v1",
        signing_secret="s" * 32,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}/api/v2/alerts"
        unauthenticated = urllib.request.Request(
            base, data=b"{}", method="POST", headers={"Content-Type": "application/json"}
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(unauthenticated, timeout=2)
        assert error.value.code == 401
        oversized = urllib.request.Request(
            base,
            data=b"x" * (MAX_BODY + 1),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": "Basic " + base64.b64encode(b"sender:" + b"p" * 32).decode(),
            },
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(oversized, timeout=2)
        assert error.value.code == 413
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
