package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// h2FaultProxy relays opaque TLS records over real TCP sockets. Only the first
// established connection is faulted; later connections to the same origin work.
// Dropping bytes leaves both TCP sockets open, unlike an EOF/RST test.
type h2FaultProxy struct {
	listener    net.Listener
	upstream    string
	mode        atomic.Int32 // 1: discard upstream, 2: discard downstream, 3: both, 4: stop reading upstream
	droppedUp   atomic.Int64
	droppedDown atomic.Int64
	accepted    atomic.Int64
	stop        chan struct{}
	acceptDone  chan struct{}
	stalledUp   atomic.Int64
	wg          sync.WaitGroup
	mu          sync.Mutex
	conns       []net.Conn
}

func newH2FaultProxy(t *testing.T, upstream string) *h2FaultProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &h2FaultProxy{listener: l, upstream: upstream, stop: make(chan struct{}), acceptDone: make(chan struct{})}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer close(p.acceptDone)
		for {
			down, err := l.Accept()
			if err != nil {
				return
			}
			first := p.accepted.Add(1) == 1
			up, err := net.DialTimeout("tcp", p.upstream, 3*time.Second)
			if err != nil {
				down.Close()
				continue
			}
			if first {
				_ = down.(*net.TCPConn).SetReadBuffer(1024)
			}
			p.mu.Lock()
			p.conns = append(p.conns, down, up)
			p.mu.Unlock()
			p.wg.Add(2)
			pump := func(dst, src net.Conn, upstream bool) {
				defer p.wg.Done()
				defer down.Close()
				defer up.Close()
				b := make([]byte, 16<<10)
				for {
					n, err := src.Read(b)
					if n > 0 {
						mode := p.mode.Load()
						if first && upstream && mode == 4 {
							p.stalledUp.Add(int64(n))
							<-p.stop
							return
						}
						drop := first && ((upstream && (mode == 1 || mode == 3)) || (!upstream && (mode == 2 || mode == 3)))
						if drop {
							if upstream {
								p.droppedUp.Add(int64(n))
							} else {
								p.droppedDown.Add(int64(n))
							}
						} else if _, e := dst.Write(b[:n]); e != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}
			go pump(up, down, true)
			go pump(down, up, false)
		}
	}()
	t.Cleanup(func() {
		l.Close()
		close(p.stop)
		// Wait for the accept loop before taking the final connection snapshot.
		<-p.acceptDone
		p.mu.Lock()
		for _, c := range p.conns {
			c.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	return p
}

func h2TestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.EnableHTTP2 = true
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func h2ProxyClient(t *testing.T, s *httptest.Server, p *h2FaultProxy) *Client {
	t.Helper()
	c := NewClientWithOptions(s.URL, "h2-node", "h2-secret", ClientOptions{})
	tr := c.http.Transport.(*http.Transport)
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	tr.TLSClientConfig = s.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tr.TLSClientConfig.InsecureSkipVerify = false
	tr.TLSClientConfig.RootCAs = roots
	tr.Proxy = nil
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, p.listener.Addr().String())
		if err == nil {
			_ = conn.(*net.TCPConn).SetWriteBuffer(1024)
		}
		return conn, err
	}
	t.Cleanup(tr.CloseIdleConnections)
	return c
}

func h2Request(c *Client, path string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return "", err
	}
	c.setAuthHeaders(req.Header)
	res, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	_, err = io.Copy(io.Discard, res.Body)
	if err != nil {
		return "", err
	}
	if res.ProtoMajor != 2 || res.TLS == nil || res.TLS.NegotiatedProtocol != "h2" {
		return "", fmt.Errorf("not TLS HTTP/2: %s", res.Proto)
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", res.StatusCode)
	}
	return res.Header.Get("X-Connection"), nil
}

func TestAgentHTTP2BlackholeRecovery(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		mode int32
	}{{"write_drop", 1}, {"read_drop", 2}, {"bidirectional_drop", 3}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var posts atomic.Int64
			s := h2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 2 || r.Header.Get("Authorization") != "Bearer h2-secret" || r.Header.Get("X-Node-ID") != "h2-node" {
					http.Error(w, "protocol/auth", 400)
					return
				}
				if r.Method == http.MethodPost {
					posts.Add(1)
				}
				w.Header().Set("X-Connection", r.RemoteAddr)
				_, _ = io.WriteString(w, "{}")
			}))
			p := newH2FaultProxy(t, s.Listener.Addr().String())
			c := h2ProxyClient(t, s, p)
			original, err := h2Request(c, "/warm", 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			again, err := h2Request(c, "/reuse", 3*time.Second)
			if err != nil || again != original {
				t.Fatalf("warm reuse: %q %q %v", original, again, err)
			}
			p.mode.Store(tc.mode)
			started := time.Now()
			// This non-idempotent POST must fail, not be replayed after losing its reply.
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			err = c.doJSON(ctx, http.MethodPost, "/ambiguous-post", map[string]string{"value": "once"}, nil)
			cancel()
			if err == nil {
				t.Fatal("blackholed POST unexpectedly succeeded")
			}
			t.Logf("canceled POST on %s: %v", original, err)
			fresh := h2ProxyClient(t, s, p)
			freshConn, err := h2Request(fresh, "/fresh", 3*time.Second)
			if err != nil || freshConn == original {
				t.Fatalf("fresh TLS h2 connection must work: %q %v", freshConn, err)
			}
			// No client recreation or CloseIdleConnections on the affected client.
			// Repeated short-deadline calls mirror periodic tasks canceling streams.
			var recovered string
			for time.Since(started) < 19*time.Second {
				recovered, err = h2Request(c, "/recover", 350*time.Millisecond)
				if err == nil {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if err != nil || recovered == original {
				t.Fatalf("stale HTTP/2 connection not retired within 19s; fresh=%s original=%s last=%v", freshConn, original, err)
			}
			if tc.mode == 2 && posts.Load() != 1 {
				t.Fatalf("ambiguous POST executions=%d, want exactly 1 (no replay)", posts.Load())
			}
			if tc.mode != 2 && posts.Load() != 0 {
				t.Fatalf("dropped POST unexpectedly reached server %d times", posts.Load())
			}
			if (tc.mode == 1 || tc.mode == 3) && p.droppedUp.Load() == 0 {
				t.Fatal("no upstream TLS bytes dropped")
			}
			if tc.mode == 2 && p.droppedDown.Load() == 0 {
				t.Fatal("no downstream TLS bytes dropped")
			}
			t.Logf("recovered in %s: old=%s fresh=%s recovered=%s dropped TLS up=%d down=%d", time.Since(started), original, freshConn, recovered, p.droppedUp.Load(), p.droppedDown.Load())
		})
	}
}

// Unlike the short-deadline scenario above, keep an ambiguous POST in flight
// until the transport's lost-PING health check closes the connection. A request
// cancellation would not exercise the transport's retry decision on that error.
func TestAgentHTTP2AmbiguousPOSTHealthCheckNoReplay(t *testing.T) {
	t.Parallel()
	var posts atomic.Int64
	postConn := make(chan string, 1)
	s := h2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.TLS == nil || r.TLS.NegotiatedProtocol != "h2" || r.Header.Get("Authorization") != "Bearer h2-secret" || r.Header.Get("X-Node-ID") != "h2-node" {
			http.Error(w, "protocol/auth", http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil || !strings.Contains(string(body), `"value":"once"`) {
				http.Error(w, "incomplete POST", http.StatusBadRequest)
				return
			}
			if posts.Add(1) == 1 {
				postConn <- r.RemoteAddr
			}
		}
		w.Header().Set("X-Connection", r.RemoteAddr)
		_, _ = io.WriteString(w, "{}")
	}))
	p := newH2FaultProxy(t, s.Listener.Addr().String())
	c := h2ProxyClient(t, s, p)
	original, err := h2Request(c, "/warm", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	again, err := h2Request(c, "/reuse", 3*time.Second)
	if err != nil || again != original || p.accepted.Load() != 1 {
		t.Fatalf("warm reuse: original=%q again=%q sockets=%d err=%v", original, again, p.accepted.Load(), err)
	}
	// Only replies (including PING ACKs) disappear. The server receives and
	// executes the complete POST; the relay does not inject an EOF or RST.
	p.mode.Store(2)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	started := time.Now()
	err = c.doJSON(ctx, http.MethodPost, "/ambiguous-post", map[string]string{"value": "once"}, nil)
	elapsed := time.Since(started)
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("POST ended through request cancellation, not health-check closure: elapsed=%s ctx=%v err=%v", elapsed, ctx.Err(), err)
	}
	// Go 1.25.12 closeForLostPing uses this error; reject generic failures
	// (including a client timeout) rather than merely asserting err != nil.
	if err == nil || !strings.Contains(err.Error(), "http2: client connection lost") {
		t.Fatalf("want lost-PING connection error, elapsed=%s err=%v", elapsed, err)
	}
	if elapsed < 10*time.Second || elapsed > 20*time.Second {
		t.Fatalf("health-check closure outside expected 10-20s window: %s", elapsed)
	}
	if posts.Load() != 1 || p.accepted.Load() != 1 {
		t.Fatalf("POST replayed or not executed: executions=%d sockets=%d", posts.Load(), p.accepted.Load())
	}
	select {
	case conn := <-postConn:
		if conn != original {
			t.Fatalf("POST did not execute on warmed connection: got=%s want=%s", conn, original)
		}
	default:
		t.Fatal("server did not receive complete POST")
	}
	if p.droppedDown.Load() == 0 || p.droppedUp.Load() != 0 {
		t.Fatalf("expected downstream-only TLS loss: up=%d down=%d", p.droppedUp.Load(), p.droppedDown.Load())
	}
	// The same client must remain usable without replacing its transport or
	// explicitly closing idle connections. This is a GET, not a POST retry.
	recovered, recoverErr := h2Request(c, "/recover", 3*time.Second)
	if recoverErr != nil || recovered == original || p.accepted.Load() != 2 {
		t.Fatalf("fresh h2 recovery: old=%s new=%s sockets=%d err=%v", original, recovered, p.accepted.Load(), recoverErr)
	}
	if posts.Load() != 1 {
		t.Fatalf("ambiguous POST executions after recovery=%d, want 1", posts.Load())
	}
	t.Logf("POST failed at health-check closure in %s (context still live): %v; executions=%d old=%s recovered=%s", elapsed, err, posts.Load(), original, recovered)
}

// A silent TCP receiver can block a TLS write, rather than accepting and
// discarding it. The real socket buffers here are small enough to force that.
func TestAgentHTTP2BlockedWriteRecovery(t *testing.T) {
	t.Parallel()
	s := h2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("X-Connection", r.RemoteAddr)
		_, _ = io.WriteString(w, "{}")
	}))
	p := newH2FaultProxy(t, s.Listener.Addr().String())
	c := h2ProxyClient(t, s, p)
	old, err := h2Request(c, "/warm", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	p.mode.Store(4)
	req, err := http.NewRequest(http.MethodPost, s.URL+"/large", strings.NewReader(strings.Repeat("x", 16<<20)))
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	// Deliberately shorter than Client.Timeout, longer than the write watchdog.
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	res, err := c.http.Do(req.WithContext(ctx))
	if res != nil {
		res.Body.Close()
	}
	if err == nil {
		t.Fatal("blocked write unexpectedly succeeded")
	}
	if ctx.Err() != nil {
		t.Fatalf("socket write did not fail before request deadline: %v", err)
	}
	writeErr := err
	if p.stalledUp.Load() == 0 {
		t.Fatal("proxy did not stall a TLS write")
	}
	fresh := h2ProxyClient(t, s, p)
	if _, err := h2Request(fresh, "/fresh", 3*time.Second); err != nil {
		t.Fatal(err)
	}
	recovered, err := h2Request(c, "/recover", 3*time.Second)
	if err != nil || recovered == old {
		t.Fatalf("blocked write connection reused: %q %v", recovered, err)
	}
	t.Logf("blocked write failed and new h2 connection recovered in %s: %v", time.Since(started), writeErr)
}

func TestAgentHTTP2HealthyConcurrencyAndCancellation(t *testing.T) {
	t.Parallel()
	s := h2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cancel" {
			<-r.Context().Done()
			return
		}
		if r.URL.Path == "/slow" {
			select {
			case <-time.After(17 * time.Second):
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("X-Connection", r.RemoteAddr)
		_, _ = io.WriteString(w, "{}")
	}))
	p := newH2FaultProxy(t, s.Listener.Addr().String())
	c := h2ProxyClient(t, s, p)
	original, err := h2Request(c, "/warm", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%3 == 0 {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				timer := time.AfterFunc(200*time.Millisecond, cancel)
				defer timer.Stop()
				err := c.doJSON(ctx, http.MethodGet, "/cancel", nil, nil)
				if !errors.Is(err, context.Canceled) {
					t.Errorf("explicit stream cancellation: %v", err)
				}
				return
			}
			conn, err := h2Request(c, "/ok", 3*time.Second)
			if err != nil || conn != original {
				t.Errorf("healthy concurrent request: conn=%q want=%q err=%v", conn, original, err)
			}
		}(i)
	}
	wg.Wait()
	// No response frames for longer than the health-check budget. The server
	// still ACKs PINGs, so a slow handler must not cause a connection reset.
	conn, err := h2Request(c, "/slow", 22*time.Second)
	if err != nil || conn != original || p.accepted.Load() != 1 {
		t.Fatalf("healthy slow stream lost connection: %q %v sockets=%d", conn, err, p.accepted.Load())
	}
	t.Log("24 concurrent streams, cancellation and 17s slow handler retained one TLS h2 connection")
}

func TestAgentHTTP2ResponseBodyTimeout(t *testing.T) {
	t.Parallel()
	s := h2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Connection", r.RemoteAddr)
		if r.URL.Path == "/body" {
			_, _ = io.WriteString(w, "{\"partial\":")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		_, _ = io.WriteString(w, "{}")
	}))
	p := newH2FaultProxy(t, s.Listener.Addr().String())
	c := h2ProxyClient(t, s, p)
	original, err := h2Request(c, "/warm", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, clientDeadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("client_timeout_%v", clientDeadline), func(t *testing.T) {
			ctx := context.Background()
			if clientDeadline {
				c.http.Timeout = 250 * time.Millisecond
				defer func() { c.http.Timeout = 30 * time.Second }()
			} else {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 250*time.Millisecond)
				defer cancel()
			}
			var response map[string]any
			started := time.Now()
			if err := c.doJSON(ctx, http.MethodGet, "/body", nil, &response); err == nil {
				t.Fatal("truncated stalled response reported success")
			}
			if time.Since(started) > 2*time.Second {
				t.Fatal("response body timeout not bounded")
			}
		})
	}
	conn, err := h2Request(c, "/after", 3*time.Second)
	if err != nil || conn != original {
		t.Fatalf("body stream cancellation damaged healthy connection: %q %v", conn, err)
	}
}

func TestAgentHTTP2RedirectDoesNotLeakAuth(t *testing.T) {
	t.Parallel()
	var leaked atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer target.Close()
	s := h2TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Header.Get("Authorization") != "Bearer h2-secret" || r.Header.Get("X-Node-ID") != "h2-node" {
			http.Error(w, "auth/protocol", 400)
			return
		}
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	p := newH2FaultProxy(t, s.Listener.Addr().String())
	c := h2ProxyClient(t, s, p)
	err := c.doJSON(context.Background(), http.MethodPost, "/redirect", map[string]string{"secret": "payload"}, nil)
	status, ok := err.(*AgentAPIStatusError)
	if !ok || status.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("redirect result: %v", err)
	}
	if leaked.Load() != 0 {
		t.Fatalf("redirect destination received %d requests", leaked.Load())
	}
}
