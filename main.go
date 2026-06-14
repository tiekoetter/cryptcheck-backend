package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tiekoetter/cryptcheck-backend/internal/host"
	"golang.org/x/net/idna"
)

const (
	defaultHost = "127.0.0.1"
	defaultPort = 7000
)

type server struct {
	analyzer host.Analyzer
	now      func() time.Time
}

type apiResponse struct {
	ID        string      `json:"id"`
	Service   string      `json:"service"`
	Host      string      `json:"host"`
	Pending   bool        `json:"pending"`
	Result    interface{} `json:"result"`
	CreatedAt string      `json:"created_at"`
	UpdatedAt string      `json:"updated_at"`
	Args      int         `json:"args"`
	RefreshAt *string     `json:"refresh_at"`
}

func main() {
	bindHost := flag.String("o", defaultHost, "address to bind")
	bindPort := flag.Int("p", defaultPort, "port to listen on")
	flag.Parse()

	srv := &server{
		analyzer: host.Analyzer{Timeout: envDuration("TCP_TIMEOUT", 10*time.Second)},
		now:      time.Now,
	}

	addr := net.JoinHostPort(*bindHost, strconv.Itoa(*bindPort))
	log.Printf("listening on %s", addr)
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       60 * time.Second,
	}
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/https/", s.handleHTTPS)
	return mux
}

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{
			"status": http.StatusMethodNotAllowed,
			"error":  "Method not allowed",
		})
		return
	}

	id, ok := strings.CutPrefix(r.URL.Path, "/https/")
	if !ok || !strings.HasSuffix(id, ".json") {
		http.NotFound(w, r)
		return
	}
	id = strings.TrimSuffix(id, ".json")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}

	targetHost, targetPort, problem := parseTarget(id)
	if problem != nil {
		writeJSON(w, http.StatusBadRequest, problem)
		return
	}

	results, err := s.analyzer.AnalyzeHTTPS(r.Context(), targetHost, targetPort)
	if err != nil {
		kind, message := classifyError(err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"status":        http.StatusServiceUnavailable,
			"error":         kind,
			"error_message": message,
		})
		return
	}

	timestamp := s.now().UTC().Format("2006-01-02T15:04:05.000Z")
	writeJSON(w, http.StatusOK, apiResponse{
		ID:        newUUID(),
		Service:   "https",
		Host:      targetHost,
		Pending:   false,
		Result:    results,
		CreatedAt: timestamp,
		UpdatedAt: timestamp,
		Args:      targetPort,
		RefreshAt: nil,
	})
}

func parseTarget(id string) (string, int, map[string]interface{}) {
	parts := strings.Split(id, ":")
	targetHost := parts[0]
	targetPort := 443
	if len(parts) > 1 {
		rawPort := parts[1]
		if containsNonDigit(rawPort) {
			return "", 0, map[string]interface{}{
				"status":        http.StatusBadRequest,
				"error":         "Invalid port",
				"error_message": fmt.Sprintf("%s is not a number", rawPort),
			}
		}
		value := rubyToInt(rawPort)
		if value < 1 || value > 65535 {
			return "", 0, map[string]interface{}{
				"status":        http.StatusBadRequest,
				"error":         "Invalid port",
				"error_message": value,
			}
		}
		targetPort = value
	}

	lowerHost := strings.ToLower(targetHost)
	asciiHost, err := idna.ToASCII(lowerHost)
	if err == nil {
		targetHost = asciiHost
	} else {
		targetHost = lowerHost
	}
	if err != nil || !validHost(targetHost) {
		return "", 0, map[string]interface{}{
			"status":  http.StatusBadRequest,
			"error":   "Invalid host",
			"message": targetHost,
		}
	}

	return targetHost, targetPort, nil
}

func classifyError(err error) (string, string) {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "Socket error", dnsErr.Error()
	}
	message := err.Error()
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "getaddrinfo"), strings.Contains(lower, "no such host"), strings.Contains(lower, "name or service not known"):
		return "Socket error", message
	case strings.Contains(lower, "network unreachable"):
		return "Address not available", message
	case strings.Contains(lower, "connection refused"):
		return "Connection refused", message
	case strings.Contains(lower, "no route to host"):
		return "No route to host", message
	case strings.Contains(lower, "timeout"):
		return "CryptCheck timeout", message
	default:
		return "CryptCheck error", message
	}
}

func validHost(host string) bool {
	for _, r := range host {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func rubyToInt(value string) int {
	if value == "" {
		return 0
	}
	bigValue, ok := new(big.Int).SetString(value, 10)
	if !ok || !bigValue.IsInt64() {
		return 65536
	}
	return int(bigValue.Int64())
}

func containsNonDigit(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return true
		}
	}
	return false
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	seconds, err := strconv.ParseFloat(value, 64)
	if err != nil || seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds * float64(time.Second))
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
