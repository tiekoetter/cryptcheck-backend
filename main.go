package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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

	"golang.org/x/net/idna"
)

const (
	defaultHost = "127.0.0.1"
	defaultPort = 7000
)

type server struct {
	timeout time.Duration
	now     func() time.Time
}

type apiResponse struct {
	Service   string      `json:"service"`
	Host      string      `json:"host"`
	Pending   bool        `json:"pending"`
	Result    interface{} `json:"result"`
	CreatedAt string      `json:"created_at"`
	UpdatedAt string      `json:"updated_at"`
	Args      int         `json:"args"`
}

type tlsResult struct {
	Hostname   string                 `json:"hostname"`
	IP         string                 `json:"ip"`
	Port       int                    `json:"port"`
	Handshakes *handshakeInfo         `json:"handshakes,omitempty"`
	States     map[string]interface{} `json:"states,omitempty"`
	Grade      string                 `json:"grade,omitempty"`
	Error      string                 `json:"error,omitempty"`
}

type certificateInfo struct {
	Subject     string                 `json:"subject"`
	Serial      string                 `json:"serial"`
	Issuer      string                 `json:"issuer"`
	Lifetime    map[string]string      `json:"lifetime"`
	Fingerprint string                 `json:"fingerprint"`
	Chain       []certificateInfo      `json:"chain,omitempty"`
	Key         map[string]interface{} `json:"key"`
	States      map[string]interface{} `json:"states"`
}

type handshakeInfo struct {
	Certs             []certificateInfo        `json:"certs"`
	DH                []interface{}            `json:"dh"`
	Protocols         []protocolInfo           `json:"protocols"`
	Ciphers           []cipherInfo             `json:"ciphers"`
	CiphersPreference []map[string]interface{} `json:"ciphers_preference"`
	Curves            []interface{}            `json:"curves"`
	CurvesPreference  interface{}              `json:"curves_preference"`
	FallbackSCSV      bool                     `json:"fallback_scsv"`
}

type protocolInfo struct {
	Protocol string                 `json:"protocol"`
	States   map[string]interface{} `json:"states"`
}

type cipherInfo struct {
	Protocol       string                 `json:"protocol"`
	Name           string                 `json:"name"`
	KeyExchange    string                 `json:"key_exchange,omitempty"`
	Authentication string                 `json:"authentication,omitempty"`
	Encryption     []interface{}          `json:"encryption,omitempty"`
	HMAC           map[string]interface{} `json:"hmac,omitempty"`
	States         map[string]interface{} `json:"states"`
}

func main() {
	host := flag.String("o", defaultHost, "address to bind")
	port := flag.Int("p", defaultPort, "port to listen on")
	flag.Parse()

	srv := &server{
		timeout: envDuration("TCP_TIMEOUT", 10*time.Second),
		now:     time.Now,
	}

	addr := net.JoinHostPort(*host, strconv.Itoa(*port))
	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, srv.routes()); err != nil {
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

	host, port, problem := parseTarget(id)
	if problem != nil {
		writeJSON(w, http.StatusBadRequest, problem)
		return
	}

	results, err := s.analyzeHTTPS(r.Context(), host, port)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"status":        http.StatusServiceUnavailable,
			"error":         classifyError(err),
			"error_message": err.Error(),
		})
		return
	}

	timestamp := s.now().UTC().Format("2006-01-02T15:04:05.000Z")
	writeJSON(w, http.StatusOK, apiResponse{
		Service:   "https",
		Host:      host,
		Pending:   false,
		Result:    results,
		CreatedAt: timestamp,
		UpdatedAt: timestamp,
		Args:      port,
	})
}

func parseTarget(id string) (string, int, map[string]interface{}) {
	parts := strings.Split(id, ":")
	host := parts[0]
	port := 443
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
		port = value
	}

	lowerHost := strings.ToLower(host)
	asciiHost, err := idna.ToASCII(lowerHost)
	if err == nil {
		host = asciiHost
	} else {
		host = lowerHost
	}
	if err != nil || !validHost(host) {
		return "", 0, map[string]interface{}{
			"status":  http.StatusBadRequest,
			"error":   "Invalid host",
			"message": host,
		}
	}

	return host, port, nil
}

func (s *server) analyzeHTTPS(ctx context.Context, host string, port int) ([]tlsResult, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses found for %s", host)
	}

	results := make([]tlsResult, 0, len(ips))
	for _, ip := range ips {
		results = append(results, probeTLS(ctx, host, ip, port, s.timeout))
	}
	return results, nil
}

func probeTLS(ctx context.Context, host string, ip net.IP, port int, timeout time.Duration) tlsResult {
	result := tlsResult{
		Hostname: host,
		IP:       ip.String(),
		Port:     port,
	}

	dialer := &net.Dialer{Timeout: timeout}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	if net.ParseIP(host) == nil {
		tlsConfig.ServerName = host
	}

	address := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	conn := tls.Client(rawConn, tlsConfig)
	defer conn.Close()
	if err := conn.HandshakeContext(ctx); err != nil {
		result.Error = err.Error()
		return result
	}

	state := conn.ConnectionState()
	protocol := cryptcheckTLSVersionName(state.Version)
	cipher := tls.CipherSuiteName(state.CipherSuite)
	valid, certError := verifyCertificates(host, state.PeerCertificates)
	result.Handshakes = &handshakeInfo{
		Certs: certificateChain(state.PeerCertificates),
		DH:    []interface{}{},
		Protocols: []protocolInfo{{
			Protocol: protocol,
			States:   emptyStates(),
		}},
		Ciphers: []cipherInfo{{
			Protocol:       protocol,
			Name:           cipher,
			KeyExchange:    cipherKeyExchange(cipher, state.Version),
			Authentication: certAuthentication(state.PeerCertificates),
			Encryption:     cipherEncryption(cipher),
			HMAC:           cipherHMAC(cipher),
			States:         emptyStates(),
		}},
		CiphersPreference: []map[string]interface{}{{
			"protocol": protocol,
			"na":       true,
		}},
		Curves:           []interface{}{},
		CurvesPreference: nil,
		FallbackSCSV:     false,
	}
	result.States = emptyStates()
	result.Grade = compatibilityGrade(valid, certError)
	return result
}

func verifyCertificates(host string, certs []*x509.Certificate) (bool, string) {
	if len(certs) == 0 {
		return false, "server did not provide a certificate"
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return false, err.Error()
	}

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	_, err = certs[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	})
	if err != nil {
		return false, err.Error()
	}
	return true, ""
}

func certificateChain(certs []*x509.Certificate) []certificateInfo {
	if len(certs) == 0 {
		return []certificateInfo{}
	}
	leaf := certificateInfoFromX509(certs[0])
	leaf.Chain = make([]certificateInfo, 0, len(certs))
	for _, cert := range certs {
		leaf.Chain = append(leaf.Chain, certificateInfoFromX509(cert))
	}
	return []certificateInfo{leaf}
}

func certificateInfoFromX509(cert *x509.Certificate) certificateInfo {
	fingerprint := sha256.Sum256(cert.Raw)
	return certificateInfo{
		Subject:     cert.Subject.String(),
		Serial:      cert.SerialNumber.String(),
		Issuer:      cert.Issuer.String(),
		Fingerprint: fmt.Sprintf("%X", fingerprint[:]),
		Lifetime: map[string]string{
			"not_before": cert.NotBefore.UTC().Format(time.RFC3339),
			"not_after":  cert.NotAfter.UTC().Format(time.RFC3339),
		},
		Key:    publicKeyInfo(cert.PublicKey),
		States: emptyStates(),
	}
}

func publicKeyInfo(key interface{}) map[string]interface{} {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return map[string]interface{}{"type": "rsa", "size": k.N.BitLen()}
	case *ecdsa.PublicKey:
		return map[string]interface{}{"type": "ecc", "size": k.Curve.Params().BitSize}
	case ed25519.PublicKey:
		return map[string]interface{}{"type": "ed25519", "size": len(k) * 8}
	default:
		return map[string]interface{}{"type": "unknown"}
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

func classifyError(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "Socket error"
	}
	return "CryptCheck error"
}

func cryptcheckTLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLSv1"
	case tls.VersionTLS11:
		return "TLSv1_1"
	case tls.VersionTLS12:
		return "TLSv1_2"
	case tls.VersionTLS13:
		return "TLSv1_3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func compatibilityGrade(valid bool, certError string) string {
	if !valid {
		if strings.Contains(strings.ToLower(certError), "not") && strings.Contains(strings.ToLower(certError), "valid for") {
			return "V"
		}
		return "T"
	}
	return "A"
}

func emptyStates() map[string]interface{} {
	return map[string]interface{}{
		"critical": map[string]interface{}{},
		"error":    map[string]interface{}{},
		"warning":  map[string]interface{}{},
		"good":     map[string]interface{}{},
		"great":    map[string]interface{}{},
		"best":     map[string]interface{}{},
	}
}

func cipherKeyExchange(name string, version uint16) string {
	if version == tls.VersionTLS13 || strings.Contains(name, "ECDHE") {
		return "ecdh"
	}
	if strings.Contains(name, "DHE") {
		return "dh"
	}
	return "rsa"
}

func certAuthentication(certs []*x509.Certificate) string {
	if len(certs) == 0 {
		return ""
	}
	switch certs[0].PublicKeyAlgorithm {
	case x509.ECDSA, x509.Ed25519:
		return "ecdsa"
	case x509.RSA:
		return "rsa"
	case x509.DSA:
		return "dss"
	default:
		return ""
	}
}

func cipherEncryption(name string) []interface{} {
	switch {
	case strings.Contains(name, "CHACHA20"):
		return []interface{}{"chacha20", 256, "stream", "aead"}
	case strings.Contains(name, "AES_256"):
		return []interface{}{"aes", 256, 128, cipherMode(name)}
	case strings.Contains(name, "AES_128"):
		return []interface{}{"aes", 128, 128, cipherMode(name)}
	default:
		return nil
	}
}

func cipherMode(name string) string {
	switch {
	case strings.Contains(name, "GCM"):
		return "gcm"
	case strings.Contains(name, "CCM"):
		return "ccm"
	default:
		return "cbc"
	}
}

func cipherHMAC(name string) map[string]interface{} {
	switch {
	case strings.Contains(name, "SHA384"):
		return map[string]interface{}{"name": "sha384", "size": 384}
	case strings.Contains(name, "SHA256"):
		return map[string]interface{}{"name": "sha256", "size": 256}
	case strings.Contains(name, "CHACHA20"):
		return map[string]interface{}{"name": "poly1305", "size": 128}
	default:
		return nil
	}
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
