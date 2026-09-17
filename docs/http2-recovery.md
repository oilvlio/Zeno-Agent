# HTTP/2 stale-connection recovery

The agent's shared API client keeps HTTP/2 enabled. A request context deadline
cancels a stream, but does not necessarily retire its connection. Go 1.25.12
counts unacknowledged stream resets against the peer's concurrency limit; this
is not a short connection-health deadline and does not imply infinite reuse.

## Minimal fix

Set `http.Transport.HTTP2` to `http.HTTP2Config` with:

- `SendPingTimeout: 10s`: send a health-check PING after no received frames.
- `PingTimeout: 5s`: close a connection that fails to acknowledge the PING.
- `WriteByteTimeout: 5s`: close a connection whose write makes no progress.

This ordinarily retires a silent connection about 15s after its last received
frame, or a blocked writer about 5s after its last write progress. Subsequent
requests can establish a new connection. This is not a strict end-to-end
request/recovery SLA: scheduling, DNS, TCP/TLS setup and continuing network
failure add latency. Requests already in flight may fail. No application-level
retry was added, especially not for ambiguous POST outcomes. Standard library
protocol-safe retry behavior is unchanged. Authentication, TLS verification,
30s client timeout, redirect refusal, and HTTP/1 fallback are unchanged.

Go 1.25.12's actual standard-library implementation reads `Transport.HTTP2` via
`http2configFromTransport` -> `http2fillNetHTTPTransportConfig` ->
`http2fillNetHTTPConfig` in `src/net/http/h2_bundle.go`. The transport field's
comment saying it has no effect is stale in this toolchain: the actual TLS
fault tests demonstrate all three configured timers taking effect. The public
standard-library field is **SendPingTimeout**, not ReadIdleTimeout (the latter
is the x/net/http2 transport name). No x/net dependency or ConfigureTransports
was necessary for the original Go 1.25.12 toolchain. The release now pins
Go 1.26.8, the latest patch of the oldest supported Go release line; the
production HTTP/2 configuration remains unchanged. Historical evidence below
retains its original toolchain labels.

## Tests

`internal/agent/client_http2_test.go` uses real TCP sockets, TLS certificate
verification and ALPN h2 against an httptest HTTP/2 server. An opaque TCP relay
selectively discards TLS bytes on the first connection without closing it;
new connections to the same origin remain functional. It does not mock the
RoundTripper or replace production timeout settings.

- Upstream, downstream and bidirectional silent drops: reuse first confirmed;
  canceled POST fails; an independent fresh h2 client works; the original client
  recovers on a different socket within 19s, without transport replacement or
  CloseIdleConnections. Downstream loss executes POST exactly once; upstream
  loss never executes it. Repeated short deadlines exercise reset accumulation.
- Ambiguous POST at health-check closure: downstream-only loss after confirmed
  reuse; the server receives the complete authenticated POST on the original
  TLS/ALPN h2 socket. The request has a 25s context (the production client timeout
  stays 30s), with no early cancellation. Require Go 1.25.12's lost-PING error
  `http2: client connection lost` within 10-20s while the context is still live.
  Require exactly one POST execution and one accepted socket when it returns;
  a subsequent GET on the same client must recover on a second h2 socket and
  leave the POST execution count at one. This covers the transport retry
  decision after health-check closure, not just canceled-stream behavior.
- Blocked write: stop reading the original TCP connection with small kernel
  buffers, send a large POST and require a write error before a 9s request
  deadline, followed by working h2 on a new connection.
- Healthy multiplexing: 24 concurrent requests including explicit cancellations;
  a 17s slow handler still responds on the original connection (PING ACKs keep
  it healthy).
- Stalled partial JSON bodies respect both context and client timeouts without
  needlessly retiring a responsive connection.
- Authenticated h2 POST redirect to plaintext is refused; destination is untouched.

The original client failed all three drop cases after 19s and the blocked-write
case at its 9s request deadline before the production change. The fixed client
recovered drops in approximately 15.1s and blocked writes in approximately 5.3s.

## Follow-up verification evidence

Using `/root/zeno-toolchains/go1.25.12/go/bin/go` (`go1.25.12 linux/amd64`):

- Negative control: temporarily set `tr.HTTP2 = nil` in the test-only client
  helper, then run the new test with `-race -count=1 -v`. It failed at
  25.012085876s with `context deadline exceeded`, specifically rejecting request
  cancellation instead of health-check closure. That temporary edit was removed;
  no production code was modified.
- `go test -race ./internal/agent -run '^TestAgentHTTP2AmbiguousPOSTHealthCheckNoReplay$' -count=5 -v`
  passed all five runs. Each returned `http2: client connection lost` with a live
  context and exactly one POST execution, then recovered on a distinct h2 socket.
  Observed closure times: 15.006579129s, 15.000706937s, 15.003684565s,
  15.004023057s and 15.005055502s. Package result: 76.193s, no race reports.
- `go test -race ./... -count=1` passed all packages (root 1.571s,
  cmd/zeno-agent 2.338s, internal/agent 34.186s), with no race reports.
- `go vet ./...` and `git diff --check` passed.

## v0.6.8 security-toolchain revalidation

The public v0.6.7 tag is preserved; its release vulnerability gate failed before
assets were published. The replacement candidate is v0.6.8.

- Go 1.25.12 reproduced govulncheck exit 3 for GO-2026-6218
  (CVE-2026-56860), GO-2026-6090 (CVE-2026-56862), GO-2026-5972
  (CVE-2026-33818), and GO-2026-5026 (CVE-2026-39821). The database lists
  Go 1.25.13 as the first fixes in that line, but Go 1.25 is no longer supported.
- Pin Go 1.26.8: the latest patch in the oldest currently supported line, rather
  than making the larger jump to Go 1.27. The official linux/amd64 archive was
  SHA-256 verified as
  `d0f743b33e8d8945e6b1f432edd15785c70507121d6e2a723b21285eddf8b57b`
  against `https://go.dev/dl/?mode=json` before extraction.
- Upgrade only `golang.org/x/sys` from v0.33.0 to v0.44.0, the first fixed
  version for GO-2026-5024 (CVE-2026-39824). This was an uncalled Windows
  package-level finding, also visible as a module-level finding on Darwin;
  it is removed rather than ignored. `go mod tidy` normalizes the minimum
  language directive to `go 1.25.0`; the selected toolchain is Go 1.26.8.
- `govulncheck@v1.6.0 -show verbose ./...` with `GOARCH=amd64` and each of
  `GOOS=linux`, `darwin`, `windows` reports **No vulnerabilities found**, with
  no residual package/module findings. The release security gate is unchanged.
- `go test ./... -count=1`, `go test -race ./... -count=1`, `go vet ./...`, and
  `staticcheck@v0.7.0 ./...` pass. Three repeated race runs of
  `go test -race ./internal/agent -run '^TestAgentHTTP2' -count=3 -v` pass in
  91.554s: silent drops recover around 15.11s, blocked writes around 5.28s,
  and ambiguous POSTs fail at 15.002753308s, 15.001185593s, and 15.001638869s
  while their contexts remain live, execute exactly once, and recover on a
  different h2 socket. Healthy concurrency, slow handlers, cancellation,
  response-body timeouts, and redirect refusal also pass.
- All seven release targets cross-build with CGO disabled (linux/arm uses
  GOARM=6). The linux/amd64 v0.6.8 candidate passes local-only `-install-check`
  and `govulncheck -mode=binary`. This is local candidate evidence, not a
  published artifact, native Windows/macOS test, or production deployment.

Logs, candidate binaries, archive metadata and checksums are retained under
`/root/zeno-h2-evidence/v068/`. No production HTTP/2 code or timer changed.

## Verifying a running agent's h2 without credentials in logs

Prefer read-only inspection of **existing client-facing TLS terminator / CDN
access logs**, selecting only timestamp, client address, request path (without
query string), and request HTTP version / negotiated ALPN. Correlate those with
Tarek's agent connection destination and local/remote socket tuple (read-only
`ss -ntp`) and heartbeat timing. A uniquely attributable agent request recorded
as HTTP/2 at that terminator proves the actual client connection used h2; an
origin log behind a CDN or reverse proxy may describe a different hop and is
not sufficient. Shared NAT or ambiguous traffic attribution must be called out.
Do not print Authorization, cookies, full request dumps, or unrestricted log
records. This uses existing telemetry only, without restarting the agent or
changing production configuration.

If the needed client-facing protocol field is not already recorded, report the
live protocol as unverified rather than enabling verbose HTTP/2 debugging.
A separately run curl/openssl probe proves endpoint capability, not the running
agent's protocol. Passive ClientHello ALPN only proves an offer; TLS 1.3 encrypts
server ALPN selection, and socket listings alone do not identify HTTP version.
No live Tarek protocol verification was performed as part of this test-only
follow-up; these are observation recommendations, not deployment evidence.

## Scope and limitations

The relay models silent transport loss and real TCP backpressure, not the exact
original kernel packet-loss cause. It proves bounded recovery for those faults,
not what initially broke Tarek/BAGE. A peer that still ACKs PINGs but stalls an
individual response remains a request-timeout problem, not a dead connection.
Existing no-JSON-response best-effort body-drain error handling is unchanged.
The health PINGs add traffic on otherwise idle connections, and a peer/proxy
that disallows these PINGs may disconnect; this is not a gRPC client policy.
No production host, service configuration, GODEBUG workaround, release, or
remote repository is modified by this change.
