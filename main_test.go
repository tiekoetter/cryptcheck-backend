package main

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRoot(t *testing.T) {
	srv := &server{timeout: time.Second, now: time.Now}
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
	host, port, problem := parseTarget("example.com")
	if problem != nil {
		t.Fatalf("problem = %#v", problem)
	}
	if host != "example.com" || port != 443 {
		t.Fatalf("target = %s:%d, want example.com:443", host, port)
	}
}

func TestParseTargetCustomPort(t *testing.T) {
	host, port, problem := parseTarget("example.com:8443")
	if problem != nil {
		t.Fatalf("problem = %#v", problem)
	}
	if host != "example.com" || port != 8443 {
		t.Fatalf("target = %s:%d, want example.com:8443", host, port)
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
	host, port, problem := parseTarget("éxample.test:443")
	if problem != nil {
		t.Fatalf("problem = %#v", problem)
	}
	if host != "xn--xample-9ua.test" {
		t.Fatalf("host = %q, want xn--xample-9ua.test", host)
	}
	if port != 443 {
		t.Fatalf("port = %d, want 443", port)
	}
}

func TestParseTargetExtraColonMatchesRubySplitAssignment(t *testing.T) {
	host, port, problem := parseTarget("example.com:443:ignored")
	if problem != nil {
		t.Fatalf("problem = %#v", problem)
	}
	if host != "example.com" || port != 443 {
		t.Fatalf("target = %s:%d, want example.com:443", host, port)
	}
}

func TestHandleHTTPSInvalidPort(t *testing.T) {
	srv := &server{timeout: time.Second, now: time.Now}
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

func TestAnalyzeHTTPS(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	upstream.Listener = listener
	upstream.StartTLS()
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, rawPort, ok := strings.Cut(u.Host, ":")
	if !ok {
		t.Fatalf("missing port in %q", u.Host)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}

	srv := &server{timeout: time.Second, now: time.Now}
	results, err := srv.analyzeHTTPS(t.Context(), "127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("no TLS results")
	}
	if results[0].Handshakes == nil {
		t.Fatal("handshakes is nil")
	}
	if len(results[0].Handshakes.Protocols) == 0 {
		t.Fatal("protocols is empty")
	}
	if len(results[0].Handshakes.Ciphers) == 0 {
		t.Fatal("ciphers is empty")
	}
	if results[0].Handshakes.Ciphers[0].Name == "" || results[0].Handshakes.Ciphers[0].Name == tls.CipherSuiteName(0) {
		t.Fatalf("cipher suite = %q", results[0].Handshakes.Ciphers[0].Name)
	}
	if results[0].States == nil {
		t.Fatal("states is nil")
	}
	if results[0].Grade == "" {
		t.Fatal("grade is empty")
	}
}
