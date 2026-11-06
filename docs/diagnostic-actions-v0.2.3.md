# Bounded network diagnostics (v0.2.3)

## Actions

| Action | Signal | Result fields | Important limit |
|---|---|---|---|
| `network.tcp_connect` | TCP connection to one configured endpoint | `tcp_connected`, address, port, duration | Port reachability only; no application protocol check |
| `network.reachability` | TCP reachability to one configured endpoint | `reachable`, address, port, duration | TCP based; no ICMP/raw socket or route mutation |
| `http.readiness` | One fixed HTTP(S) GET path | `http_status`, `ready`, `tls_verified`, content type | 2xx only is ready; redirects are not followed; the response body is not read |
| `postgresql.protocol_available` | PostgreSQL SSL negotiation response | `protocol_available`, `ssl_supported`, `authentication_attempted` | Sends only the 8-byte PostgreSQL SSLRequest; no credentials, SQL, or data access; does not prove authentication or database readiness |

Every action is registered read-only and has a strict Pydantic argument model. The only runbook argument is an `endpoint_id` alias. It cannot carry a host, URL, port, shell command, path, header, credential, or redirect destination. Action timeout is at most 10 seconds.

## Two-part endpoint authorization

The source managed host's inventory defines endpoint IDs and exact private IPv4 address, port, protocol, and (for HTTP only) path. The same endpoint ID must appear in that host's `allowed_probe_targets`, and the action itself must appear in `diagnostic_actions`. Missing entries retain default-deny. Example only; replace placeholders after operator review and do not run against the homelab without explicit policy authorization:

```yaml
# inventory fragment (fictional TEST-NET-like lab values; not enabled)
hosts:
  example-app:
    address: 192.0.2.10
    user: runbookos
    role: application-server
    ssh_profile: homelab
    probe_targets:
      postgres_listener:
        protocol: postgresql
        address: 192.0.2.20
        port: 5432
      application_readiness:
        protocol: https
        address: 192.0.2.10
        port: 8443
        path: /health/ready
```

```yaml
# policy fragment, scoped to source host example-app
hosts:
  example-app:
    diagnostic_actions:
      - network.tcp_connect
      - network.reachability
      - http.readiness
      - postgresql.protocol_available
    allowed_probe_targets:
      - postgres_listener
      - application_readiness
```

The probe target accepts IPv4 literals only and rejects public, loopback, link-local, multicast, reserved, and unspecified addresses. DNS resolution is not used, preventing DNS rebinding. The inventory and policy files are bound into the execution plan hashes. Changing either after planning invalidates the plan.

`https` uses Python's default certificate store and hostname/IP certificate validation. There is no insecure TLS switch. HTTP responses are not followed if they redirect, even to another private address. A response is considered ready only for 2xx; even then it proves only that configured path returned 2xx. It does not prove all dependencies are healthy.

The Postgres probe reports protocol negotiation, not readiness for a particular user/database. It does not continue into TLS, send a startup message, authenticate, or query data. If a deployment requires auth or server changes to establish readiness, use a separately reviewed check; this action will not add access or credentials.

## Evidence interpretation

Keep assertions and incident conclusions specific to their signal:

- `systemd.is_active` means the unit is active; it says nothing about its listening socket.
- `network.tcp_connect` means a TCP handshake completed; it says nothing about HTTP, TLS identity, application readiness, or dependencies.
- `http.readiness` means one configured endpoint returned 2xx with valid TLS when HTTPS was selected; a shallow endpoint may still hide a broken dependency.
- `postgresql.protocol_available` means an unauthenticated SSL negotiation response was received; it does not verify credentials, database selection, or query health.
- `network.routes` reports local route-table entries; it does not establish packet delivery.

The sample [application dependency readiness runbook](../examples/runbooks/dependency-readiness.yml) shows the separate assertions. The example has no endpoint configured or policy allow by default, so it must be explicitly reviewed and configured before planning returns `ready`.

## Testing boundary

Unit tests mock sockets and HTTP clients, validate endpoint schemas, and inspect generated evidence without making network calls. Live tests against targets are not part of this milestone. Do not use the production homelab as an endpoint-test target until its inventory and policy have been separately reviewed and approved.
