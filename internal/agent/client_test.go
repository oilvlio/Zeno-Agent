package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateControllerURLRequiresTLSForRemoteHosts(t *testing.T) {
	valid := []string{
		"https://zeno.example.com",
		"http://localhost:18980",
		"http://localhost.:18980",
		"http://127.0.0.1:18980",
		"http://127.0.0.2:18980",
		"http://[::1]:18980",
		"http://[::ffff:127.0.0.1]:18980",
		"http://[::ffff:7f00:1]:18980",
	}
	for _, value := range valid {
		if err := ValidateControllerURLWithOptions(value, false); err != nil {
			t.Fatalf("ValidateControllerURLWithOptions(%q) = %v, want valid", value, err)
		}
	}
	invalid := []string{
		"http://zeno.example.com",
		"http://localhost.example.com",
		"http://127.0.0.1.evil.example",
		"http://[::ffff:192.168.1.1]:18980",
		"ws://127.0.0.1:18980",
		"https://user:pass@zeno.example.com",
		"https://zeno.example.com?token=secret",
		"not a url",
	}
	for _, value := range invalid {
		if err := ValidateControllerURLWithOptions(value, false); err == nil {
			t.Fatalf("ValidateControllerURLWithOptions(%q) succeeded, want rejection", value)
		}
	}
}

func TestClientRejectsRemotePlainHTTPBeforeSendingToken(t *testing.T) {
	client := newTestClient("http://198.51.100.10:18980", "node", "secret-token")
	err := client.PostHeartbeat(context.Background(), "online", "test", time.Now())
	if err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("PostHeartbeat error = %v, want remote HTTP rejection", err)
	}
}

func TestValidateControllerURLExplicitInsecureHTTPContract(t *testing.T) {
	allowed := []string{
		"http://198.51.100.10:80",
		"http://198.51.100.10:18980",
		"http://[2001:db8::10]:18980",
		"http://[::ffff:192.168.1.1]:18980",
	}
	for _, value := range allowed {
		if err := ValidateControllerURLWithOptions(value, false); err == nil {
			t.Fatalf("default validation accepted insecure URL %q", value)
		}
		if err := ValidateControllerURLWithOptions(value, true); err != nil {
			t.Fatalf("opt-in validation rejected %q: %v", value, err)
		}
	}
	for _, value := range []string{
		"http://198.51.100.10",
		"http://198.51.100.10:0",
		"http://198.51.100.10:65536",
		"http://[2001:db8::10]",
		"http://zeno.example.com:18980",
		"http://user@198.51.100.10:18980",
	} {
		if err := ValidateControllerURLWithOptions(value, true); err == nil {
			t.Fatalf("opt-in validation accepted out-of-contract URL %q", value)
		}
	}
	client := NewClientWithOptions("http://198.51.100.10:18980", "node", "token", ClientOptions{AllowInsecureHTTP: true})
	if got, err := client.PresenceWebSocketURL(); err != nil || got != "ws://198.51.100.10:18980/api/agent/v1/presence/ws" {
		t.Fatalf("opt-in websocket URL = %q, %v", got, err)
	}
}

func TestClientAddsAgentAuthHeadersAndPostsState(t *testing.T) {
	var sawPath, sawNode, sawAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		sawNode = r.Header.Get("X-Node-ID")
		sawAuth = r.Header.Get("Authorization")
		var body StateSample
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode state body: %v", err)
		}
		if body.SampleID == "" || body.IdempotencyKey != body.SampleID {
			t.Fatalf("state id fields = sample_id %q idempotency_key %q, want matching generated ids", body.SampleID, body.IdempotencyKey)
		}
		if body.TS != 1782990000 || body.CPUPercent != 12.5 || body.Load1 != 0.42 || body.Load5 != 0.35 || body.Load15 != 0.28 || body.SwapUsedBytes != 512 || body.SwapTotalBytes != 2048 || body.ProcessCount != 88 || body.TCPConnectionCount != 34 || body.UDPConnectionCount != 12 || body.NetOutSpeedBps != 1024 {
			t.Fatalf("state body = %+v, want exact sample with extra metrics", body)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client := newTestClient(server.URL, "node-a", "secret-token")
	sample := StateSample{
		TS:                 1782990000,
		CPUPercent:         12.5,
		Load1:              0.42,
		Load5:              0.35,
		Load15:             0.28,
		SwapUsedBytes:      512,
		SwapTotalBytes:     2048,
		NetOutSpeedBps:     1024,
		ProcessCount:       88,
		TCPConnectionCount: 34,
		UDPConnectionCount: 12,
	}
	err := client.PostState(context.Background(), sample)
	if err != nil {
		t.Fatalf("post state: %v", err)
	}
	if sawPath != "/api/agent/v1/state" || sawNode != "node-a" || sawAuth != "Bearer secret-token" {
		t.Fatalf("path/node/auth = %q/%q/%q, want state/node-a/bearer", sawPath, sawNode, sawAuth)
	}
}

func TestClientPostStateReusesGeneratedIDForSameSampleRetry(t *testing.T) {
	var ids []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/v1/state" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		var body StateSample
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode state body: %v", err)
		}
		if body.SampleID == "" || body.IdempotencyKey != body.SampleID {
			t.Fatalf("state id fields = sample_id %q idempotency_key %q, want matching generated ids", body.SampleID, body.IdempotencyKey)
		}
		ids = append(ids, body.SampleID)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client := newTestClient(server.URL, "node-a", "secret-token")
	sample := StateSample{TS: 1782990000, CPUPercent: 12.5, MemoryUsedBytes: 1024, MemoryTotalBytes: 2048, DiskUsedBytes: 4096, DiskTotalBytes: 8192, NetInTotalBytes: 10, NetOutTotalBytes: 20, UptimeSeconds: 30}
	if err := client.PostState(context.Background(), sample); err != nil {
		t.Fatalf("first post state: %v", err)
	}
	if err := client.PostState(context.Background(), sample); err != nil {
		t.Fatalf("retry post state: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("posted ids = %+v, want two posts", ids)
	}
	if ids[0] != ids[1] {
		t.Fatalf("same sample retry ids = %q then %q, want stable id", ids[0], ids[1])
	}
}

func TestClientFetchesProbeConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/v1/probe-targets" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("X-Node-ID") != "node-a" || r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("missing auth headers on target fetch")
		}
		_ = json.NewEncoder(w).Encode(ProbeTargetsResponse{Version: 7, Targets: []ProbeTarget{{ID: "google", Name: "Google", Type: "tcping", Address: "8.8.8.8", Count: 3, TimeoutMS: 1000, IntervalSec: 60}}})
	}))
	defer server.Close()

	client := newTestClient(server.URL+"/", "node-a", "token")
	config, err := client.FetchProbeConfig(context.Background())
	if err != nil {
		t.Fatalf("fetch probe config: %v", err)
	}
	if config.Version != 7 || len(config.Targets) != 1 || config.Targets[0].ID != "google" {
		t.Fatalf("config = %+v, want version 7 with google", config)
	}
}

func TestProbeSpoolRejectsMixedConfigVersionsBeforePersisting(t *testing.T) {
	_, err := marshalProbeResults([]ProbeRound{
		{RoundID: "round-legacy", ConfigVersion: 0},
		{RoundID: "round-current", ConfigVersion: 7},
	})
	if err == nil || !strings.Contains(err.Error(), "mixed probe config versions") {
		t.Fatalf("error = %v, want mixed-version rejection", err)
	}
}

func TestClientErrorDoesNotExposeControllerResponseBody(t *testing.T) {
	const secret = "proxy-secret-must-not-leak"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(strings.Repeat(secret, 1024)))
	}))
	defer server.Close()

	client := newTestClient(server.URL, "node-a", "token")
	err := client.PostHeartbeat(context.Background(), "online", "test", time.Now())
	if err == nil {
		t.Fatal("expected controller error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("controller response body leaked in error: %v", err)
	}
	if !strings.Contains(err.Error(), "returned 502") {
		t.Fatalf("error = %q, want status without response body", err)
	}
}

func TestClientRejectsOversizedJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"targets":[],"padding":"` + strings.Repeat("a", int(maxAgentAPIJSONBodyBytes)) + `"}`))
	}))
	defer server.Close()

	client := newTestClient(server.URL, "node-a", "token")
	_, err := client.FetchProbeConfig(context.Background())
	if err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("error = %v, want bounded response error", err)
	}
}

func TestClientDoesNotFollowRedirectsWithBearerToken(t *testing.T) {
	var leakHits int
	leakServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leakHits++
		if r.Header.Get("Authorization") != "" {
			t.Fatalf("redirect target received Authorization header %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer leakServer.Close()

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, leakServer.URL+"/leak", http.StatusFound)
	}))
	defer redirectServer.Close()

	client := newTestClient(redirectServer.URL, "node", "secret-token")
	err := client.PostHeartbeat(context.Background(), "online", "test", time.Now())
	if err == nil || !isAgentAPIStatus(err, http.StatusFound) {
		t.Fatalf("PostHeartbeat error = %v, want local 302 status error", err)
	}
	if leakHits != 0 {
		t.Fatalf("redirect target hit count = %d, want 0", leakHits)
	}
}

func TestStateValidityFieldsRemainOptionalAndCanRepresentFalse(t *testing.T) {
	legacyPayload, err := json.Marshal(StateSample{})
	if err != nil {
		t.Fatalf("marshal state without validity fields: %v", err)
	}
	if strings.Contains(string(legacyPayload), "net_totals_valid") || strings.Contains(string(legacyPayload), "connection_counts_valid") {
		t.Fatalf("nil optional validity fields were emitted: %s", legacyPayload)
	}

	invalid := false
	payload, err := json.Marshal(StateSample{NetTotalsValid: &invalid, ConnectionCountsValid: &invalid})
	if err != nil {
		t.Fatalf("marshal invalid state: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decode invalid state JSON: %v", err)
	}
	if value, ok := decoded["net_totals_valid"]; !ok || value != false {
		t.Fatalf("net_totals_valid = %v (present=%v), want explicit false", value, ok)
	}
	if value, ok := decoded["connection_counts_valid"]; !ok || value != false {
		t.Fatalf("connection_counts_valid = %v (present=%v), want explicit false", value, ok)
	}
}
