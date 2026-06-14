package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tiekoetter/cryptcheck-backend/internal/host"
)

func TestRoot(t *testing.T) {
	srv := &server{now: time.Now}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()

	srv.routes().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusOK)
	}
	if body := res.Body.String(); body != "" {
		t.Fatalf("body = %q, want empty", body)
	}
}

func TestParseTargetDefaultPort(t *testing.T) {
	targetHost, targetPort, problem := parseTarget("example.com")
	if problem != nil {
		t.Fatalf("problem = %#v", problem)
	}
	if targetHost != "example.com" || targetPort != 443 {
		t.Fatalf("target = %s:%d, want example.com:443", targetHost, targetPort)
	}
}

func TestParseTargetCustomPort(t *testing.T) {
	targetHost, targetPort, problem := parseTarget("example.com:8443")
	if problem != nil {
		t.Fatalf("problem = %#v", problem)
	}
	if targetHost != "example.com" || targetPort != 8443 {
		t.Fatalf("target = %s:%d, want example.com:8443", targetHost, targetPort)
	}
}

func TestParseTargetInvalidPort(t *testing.T) {
	_, _, problem := parseTarget("example.com:abc")
	if problem == nil {
		t.Fatal("problem is nil")
	}
	if problem["error"] != "Invalid port" {
		t.Fatalf("error = %v, want Invalid port", problem["error"])
	}
	if problem["error_message"] != "abc is not a number" {
		t.Fatalf("error_message = %v, want abc is not a number", problem["error_message"])
	}
}

func TestParseTargetEmptyPortMatchesRubyToI(t *testing.T) {
	_, _, problem := parseTarget("example.com:")
	if problem == nil {
		t.Fatal("problem is nil")
	}
	if problem["error"] != "Invalid port" {
		t.Fatalf("error = %v, want Invalid port", problem["error"])
	}
	if problem["error_message"] != 0 {
		t.Fatalf("error_message = %#v, want numeric 0", problem["error_message"])
	}
}

func TestParseTargetOutOfRangePortUsesNumber(t *testing.T) {
	_, _, problem := parseTarget("example.com:65536")
	if problem == nil {
		t.Fatal("problem is nil")
	}
	if problem["error_message"] != 65536 {
		t.Fatalf("error_message = %#v, want numeric 65536", problem["error_message"])
	}
}

func TestParseTargetInvalidHost(t *testing.T) {
	_, _, problem := parseTarget("bad host")
	if problem == nil {
		t.Fatal("problem is nil")
	}
	if problem["error"] != "Invalid host" {
		t.Fatalf("error = %v, want Invalid host", problem["error"])
	}
	if problem["message"] != "bad host" {
		t.Fatalf("message = %v, want bad host", problem["message"])
	}
	if _, ok := problem["error_message"]; ok {
		t.Fatal("invalid host response must use legacy message field, not error_message")
	}
}

func TestParseTargetIDN(t *testing.T) {
	targetHost, targetPort, problem := parseTarget("éxample.test:443")
	if problem != nil {
		t.Fatalf("problem = %#v", problem)
	}
	if targetHost != "xn--xample-9ua.test" {
		t.Fatalf("host = %q, want xn--xample-9ua.test", targetHost)
	}
	if targetPort != 443 {
		t.Fatalf("port = %d, want 443", targetPort)
	}
}

func TestParseTargetExtraColonMatchesRubySplitAssignment(t *testing.T) {
	targetHost, targetPort, problem := parseTarget("example.com:443:ignored")
	if problem != nil {
		t.Fatalf("problem = %#v", problem)
	}
	if targetHost != "example.com" || targetPort != 443 {
		t.Fatalf("target = %s:%d, want example.com:443", targetHost, targetPort)
	}
}

func TestHandleHTTPSInvalidPort(t *testing.T) {
	srv := &server{now: time.Now}
	req := httptest.NewRequest(http.MethodGet, "/https/example.com:abc.json", nil)
	res := httptest.NewRecorder()

	srv.routes().ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusBadRequest)
	}
	var payload map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["error"] != "Invalid port" {
		t.Fatalf("error = %v, want Invalid port", payload["error"])
	}
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{&net.DNSError{Err: "no such host", Name: "invalid.test"}, "Socket error"},
	}
	for _, tc := range tests {
		got, _ := classifyError(tc.err)
		if got != tc.want {
			t.Fatalf("classify(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestAnalyzeHTTPSDNSFailure(t *testing.T) {
	analyzer := host.Analyzer{Timeout: time.Second}
	_, err := analyzer.AnalyzeHTTPS(t.Context(), "nonexistent-domain-xyz12345.invalid", 443)
	if err == nil {
		t.Fatal("expected DNS failure")
	}
	kind, _ := classifyError(err)
	if kind != "Socket error" {
		t.Fatalf("error kind = %q, want Socket error", kind)
	}
}

func TestAnalyzeHTTPSIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration test in short mode")
	}

	srv := &server{
		analyzer: host.Analyzer{Timeout: 2 * time.Minute},
		now:      time.Now,
	}
	req := httptest.NewRequest(http.MethodGet, "/https/example.com.json", nil)
	res := httptest.NewRecorder()

	srv.routes().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", res.Code, http.StatusOK, res.Body.String())
	}

	var payload apiResponse
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Service != "https" {
		t.Fatalf("service = %q, want https", payload.Service)
	}
	if payload.Host != "example.com" {
		t.Fatalf("host = %q, want example.com", payload.Host)
	}
	if payload.Pending {
		t.Fatal("pending = true, want false")
	}
	if payload.Args != 443 {
		t.Fatalf("args = %d, want 443", payload.Args)
	}
	if payload.ID == "" {
		t.Fatal("id is empty")
	}
	if payload.RefreshAt != nil {
		t.Fatalf("refresh_at = %v, want nil", *payload.RefreshAt)
	}

	raw, err := json.Marshal(payload.Result)
	if err != nil {
		t.Fatal(err)
	}
	var results []map[string]interface{}
	if err := json.Unmarshal(raw, &results); err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("no results")
	}
	if results[0]["grade"] == nil || results[0]["grade"] == "" {
		t.Fatal("grade is empty")
	}
	handshakes, ok := results[0]["handshakes"].(map[string]interface{})
	if !ok {
		t.Fatal("handshakes missing")
	}
	if handshakes["protocols"] == nil {
		t.Fatal("protocols missing")
	}
	if handshakes["ciphers"] == nil {
		t.Fatal("ciphers missing")
	}
}
