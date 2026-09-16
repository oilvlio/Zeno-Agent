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
is necessary for the pinned Go 1.25.12 toolchain.

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
