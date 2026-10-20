# Webhook authentication and rotation (v0.3.1)

## Source identity and key storage

The webhook is optional and remains a foreground loopback listener. The auth YAML contains only source names, enabled state, key IDs, key status, expiry, and the name of an environment variable. It never contains the HMAC key. A `key_id` maps to exactly one configured source; per-source mode also requires globally unique IDs. The source identity returned by this mapping is authoritative. Native RunbookOS JSON must have exactly the same `source`; a mismatch is rejected before ingestion. Alertmanager v2 source is assigned from the authenticated key and is never copied from a payload field.

Generate each HMAC secret using an operator secret manager or a cryptographically secure generator, deliver it out of band, and expose it only in the foreground process environment. A secret must be at least 32 bytes. Do not put secret values in YAML, SQLite, audit events, shell history, request URLs, or logs. Avoid `export KEY=value` in shared shell history; inject from a protected secret manager/environment file with restrictive permissions.

```sh
runbookos webhook serve --auth-config config/webhook-sources.example.yml --host 127.0.0.1
```

Per-source requests include `X-RunbookOS-Key-Id`, `X-RunbookOS-Timestamp`, `X-RunbookOS-Nonce`, and `X-RunbookOS-Signature`. The signature is lowercase hex HMAC-SHA256 over:

```text
key_id + LF + timestamp + LF + nonce + LF + exact_raw_body
```

The timestamp is Unix seconds and is checked against configured skew (300 seconds by default, bounded 30–900). Nonces are random 16–128 character URL-safe values. They are stored under one global namespace, so replay with another source or key version is rejected. Request size is at most 64 KiB; concurrency and rate limits remain bounded and in-memory for the single foreground process.

## Rotation sequence

1. Add a new unique key ID as `active`, make the old active key `grace` with an explicit UTC `expires_at`, and set `active_key_id` to the new key. Keep each secret in its own environment variable.
2. Deliver the new secret and key ID to the sender. Start/restart the foreground webhook only during a planned test window. Startup appends `webhook.keyring_loaded` to audit with config hash and source/key status metadata only.
3. Verify the sender uses the new key. Requests signed with the grace key are accepted only before its expiry.
4. After sender cutover, change old key state to `revoked` (or remove it), unset its secret from the process environment, restart, and verify audit chain.
5. Retain audit and backup evidence for the key state transition; never reuse key IDs or nonce values.

Revoked, unknown, disabled-source, malformed-signature, expired-grace-key, and timestamp-expired requests are rejected with generic authentication responses. Secret values and signature bytes are never written to audit. Audit retains the configured key ID on accepted ingestion and key status/config digest at listener start.

Before opening the listener, startup checks that every enabled source's active key is present in the environment and has at least 32 bytes. A missing active key fails startup before the keyring-loaded audit event is written. Grace-key material is checked when a request uses that key, so operators should verify both active and grace secrets during a planned rotation window.

## Explicit legacy compatibility

`mode: legacy_single_source` is a deliberate one-source-only compatibility mode for the v0.3.0 signer, which authenticated `timestamp + LF + nonce + LF + body` without a key-ID header. It still binds to one configured source, validates body `source`, has a 32-byte key, timestamp window, global nonce replay protection, size/concurrency/rate bounds, and loopback binding. There is no automatic fallback from per-source mode. New integrations should use `per_source`; legacy mode should be removed after clients migrate.

## Alertmanager adapter

For `Content-Type: application/vnd.prometheus.alertmanager.v2+json`, the listener accepts Alertmanager webhook payload version `4`. It maps a homogeneous group (one `target_alias`, `service`, and category) to one RunbookOS alert. Group key plus sorted fingerprints form stable correlation identity; group status contributes to delivery ID so a later `resolved` message is not treated as conflicting payload. A `resolved` event is informational (`info`) and never transitions the incident. Mixed target/service/category groups and missing target aliases are rejected. The provider does not control a RunbookOS source identity.

This adapter has offline fixture coverage only. Live Alertmanager compatibility has not been verified.
