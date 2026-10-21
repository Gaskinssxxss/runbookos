"""Canonical loopback endpoint settings for the v0.6.0 test-only harness."""

LOOPBACK = "127.0.0.1"
ACCEPTANCE_PORT = 18080
PROVIDER_ENDPOINT = f"http://{LOOPBACK}:{ACCEPTANCE_PORT}/v1"
