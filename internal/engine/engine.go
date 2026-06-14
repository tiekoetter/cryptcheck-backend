package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tiekoetter/cryptcheck-backend/internal/cert"
	"github.com/tiekoetter/cryptcheck-backend/internal/cipher"
	"github.com/tiekoetter/cryptcheck-backend/internal/grade"
	"github.com/tiekoetter/cryptcheck-backend/internal/method"
	"github.com/tiekoetter/cryptcheck-backend/internal/state"
)

const (
	defaultTCPTimeout = 10 * time.Second
	longHSTS          = 6 * 30 * 24 * 60 * 60
)

type Config struct {
	TCPTimeout time.Duration
}

type Server struct {
	Hostname string
	IP       string
	Port     int

	supportedMethods  []method.Info
	supportedCiphers  map[string][]cipher.Info
	cipherConnections map[string]map[string]*tls.ConnectionState
	preferences       map[string]interface{}
	supportedCurves   []string
	curvesPreference  interface{}
	fallbackSCSV      interface{}
	certs             []cert.Info
	valid             bool
	trusted           bool
	hsts              interface{}
}

type probeSuite struct {
	id         uint16
	name       string
	minVersion uint16
	maxVersion uint16
}

func Analyze(ctx context.Context, hostname, ip string, port int, cfg Config) (*Server, error) {
	if cfg.TCPTimeout <= 0 {
		cfg.TCPTimeout = defaultTCPTimeout
	}

	s := &Server{
		Hostname:          hostname,
		IP:                ip,
		Port:              port,
		supportedCiphers:  make(map[string][]cipher.Info),
		cipherConnections: make(map[string]map[string]*tls.ConnectionState),
		preferences:       make(map[string]interface{}),
		valid:             true,
		trusted:           true,
	}

	suites := allProbeSuites()
	s.probeProtocols(ctx, cfg, suites)
	if len(s.supportedMethods) == 0 {
		return nil, fmt.Errorf("TLS seems not supported on this server")
	}
	s.probeCiphers(ctx, cfg, suites)
	s.collectCertificates(hostname)
	s.probeCurves(ctx, cfg)
	s.probePreferences(ctx, cfg, suites)
	s.checkFallback(ctx, cfg, suites)
	return s, nil
}

func allProbeSuites() []probeSuite {
	seen := make(map[uint16]struct{})
	out := make([]probeSuite, 0)
	for _, suite := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		if _, ok := seen[suite.ID]; ok {
			continue
		}
		if strings.HasPrefix(suite.Name, "TLS_AES_") || strings.HasPrefix(suite.Name, "TLS_CHACHA20_POLY1305") {
			continue
		}
		seen[suite.ID] = struct{}{}
		out = append(out, probeSuite{
			id:         suite.ID,
			name:       suite.Name,
			minVersion: tls.VersionTLS10,
			maxVersion: tls.VersionTLS12,
		})
	}
	return out
}

var probeProtocols = []uint16{tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10}

var curveProbeOrder = []struct {
	name string
	id   tls.CurveID
}{
	{"secp384r1", tls.CurveP384},
	{"prime256v1", tls.CurveP256},
	{"secp521r1", tls.CurveP521},
}

var ecdheCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

func (s *Server) probeProtocols(ctx context.Context, cfg Config, suites []probeSuite) {
	for _, proto := range probeProtocols {
		name := method.VersionName(proto)
		if name == "" {
			continue
		}
		connState, err := s.handshake(ctx, cfg, handshakeOptions{
			minVersion: proto,
			maxVersion: proto,
			suites:     suiteIDsForVersion(suites, proto),
		})
		if err != nil {
			continue
		}
		_ = connState
		s.supportedMethods = append(s.supportedMethods, method.Info{Protocol: name})
	}
}

func (s *Server) probeCiphers(ctx context.Context, cfg Config, suites []probeSuite) {
	for _, methodInfo := range s.supportedMethods {
		proto := versionFromName(methodInfo.Protocol)
		protoSuites := suitesForVersion(suites, proto)
		seen := make(map[string]struct{})
		s.cipherConnections[methodInfo.Protocol] = make(map[string]*tls.ConnectionState)
		for _, suite := range protoSuites {
			connState, err := s.handshake(ctx, cfg, handshakeOptions{
				minVersion: proto,
				maxVersion: proto,
				suites:     []uint16{suite.id},
			})
			if err != nil {
				continue
			}
			openSSLName := cipher.GoNameToOpenSSL(suite.name)
			if _, ok := seen[openSSLName]; ok {
				continue
			}
			seen[openSSLName] = struct{}{}
			info := cipher.Info{Protocol: methodInfo.Protocol, Name: openSSLName}
			s.supportedCiphers[methodInfo.Protocol] = append(s.supportedCiphers[methodInfo.Protocol], info)
			stateCopy := *connState
			s.cipherConnections[methodInfo.Protocol][openSSLName] = &stateCopy
		}
	}
}

func (s *Server) probePreferences(ctx context.Context, cfg Config, suites []probeSuite) {
	for _, methodInfo := range s.supportedMethods {
		ciphers := s.supportedCiphers[methodInfo.Protocol]
		if len(ciphers) < 2 {
			s.preferences[methodInfo.Protocol] = map[string]interface{}{"protocol": methodInfo.Protocol, "na": true}
			continue
		}
		proto := versionFromName(methodInfo.Protocol)
		a, b := ciphers[0], ciphers[1]
		_, errAB := s.negotiatedCipher(ctx, cfg, proto, a.Name, b.Name, suites)
		_, errBA := s.negotiatedCipher(ctx, cfg, proto, b.Name, a.Name, suites)
		// CryptCheck compares Cipher objects by identity, not negotiated name.
		// When both probes succeed it always records client preference.
		if errAB == nil && errBA == nil {
			s.preferences[methodInfo.Protocol] = map[string]interface{}{"protocol": methodInfo.Protocol, "client": true}
			continue
		}
		names := make([]string, len(ciphers))
		for i, c := range ciphers {
			names[i] = c.Name
		}
		ordered := sortCipherPreference(ctx, s, cfg, proto, names, suites)
		pref := make([]map[string]interface{}, 0, len(ordered))
		for _, name := range ordered {
			for _, c := range ciphers {
				if c.Name == name {
					pref = append(pref, c.ToMap())
					break
				}
			}
		}
		s.preferences[methodInfo.Protocol] = map[string]interface{}{"protocol": methodInfo.Protocol, "cipher_suite": pref}
	}
}

func sortCipherPreference(ctx context.Context, s *Server, cfg Config, proto uint16, names []string, suites []probeSuite) []string {
	if len(names) < 2 {
		return names
	}
	sort.SliceStable(names, func(i, j int) bool {
		first, err := s.negotiatedCipher(ctx, cfg, proto, names[i], names[j], suites)
		if err != nil {
			return false
		}
		return first == names[i]
	})
	return names
}

func (s *Server) probeCurves(ctx context.Context, cfg Config) {
	if len(s.certs) == 0 {
		s.curvesPreference = nil
		return
	}

	certCurve := certCurveID(s.certs[0].Certificate)
	seen := make(map[string]struct{})
	for _, curve := range curveProbeOrder {
		prefs := []tls.CurveID{curve.id}
		if curve.id != certCurve {
			prefs = append(prefs, certCurve)
		}
		connState, err := s.handshake(ctx, cfg, handshakeOptions{
			minVersion: tls.VersionTLS12,
			maxVersion: tls.VersionTLS12,
			suites:     ecdheCiphers,
			curves:     prefs,
		})
		if err != nil {
			continue
		}
		cipherName := tls.CipherSuiteName(connState.CipherSuite)
		if !strings.Contains(cipherName, "ECDHE") {
			continue
		}
		if connState.CurveID != 0 && connState.CurveID != curve.id {
			continue
		}
		if _, ok := seen[curve.name]; ok {
			continue
		}
		seen[curve.name] = struct{}{}
		s.supportedCurves = append(s.supportedCurves, curve.name)
	}
	s.curvesPreference = nil
}

func certCurveID(certificate *x509.Certificate) tls.CurveID {
	switch cert.CertCurveName(certificate) {
	case "secp384r1":
		return tls.CurveP384
	case "secp521r1":
		return tls.CurveP521
	default:
		return tls.CurveP256
	}
}

func (s *Server) checkFallback(ctx context.Context, cfg Config, suites []probeSuite) {
	if len(s.supportedMethods) < 2 {
		s.fallbackSCSV = nil
		return
	}
	second := s.supportedMethods[1]
	proto := versionFromName(second.Protocol)
	_, err := s.handshake(ctx, cfg, handshakeOptions{
		minVersion: proto,
		maxVersion: proto,
		suites:     suiteIDsForVersion(suites, proto),
		fallback:   true,
	})
	if err != nil {
		s.fallbackSCSV = true
		return
	}
	s.fallbackSCSV = false
}

func (s *Server) collectCertificates(hostname string) {
	seen := make(map[string]struct{})
	for proto, ciphers := range s.cipherConnections {
		for name, connState := range ciphers {
			if len(connState.PeerCertificates) == 0 {
				continue
			}
			leaf := connState.PeerCertificates[0]
			fp := cert.Fingerprint(leaf)
			if _, ok := seen[fp]; ok {
				continue
			}
			seen[fp] = struct{}{}
			valid, trusted := cert.Verify(hostname, connState.PeerCertificates)
			if !valid {
				s.valid = false
			}
			if !trusted {
				s.trusted = false
			}
			s.certs = append(s.certs, cert.Info{
				Certificate: leaf,
				Chain:       connState.PeerCertificates,
				Valid:       valid,
				Trusted:     trusted,
			})
			_ = proto
			_ = name
		}
	}
}

func (s *Server) FetchHSTS(ctx context.Context, timeout time.Duration) {
	if timeout <= 0 {
		timeout = defaultTCPTimeout
	}
	port := ""
	if s.Port != 443 {
		port = ":" + strconv.Itoa(s.Port)
	}
	url := fmt.Sprintf("https://%s%s/", s.Hostname, port)
	client := &httpClient{timeout: timeout}
	maxAge, ok := client.headHSTS(ctx, url)
	if ok {
		s.hsts = maxAge
		return
	}
	s.hsts = nil
}

func (s *Server) ToMap() map[string]interface{} {
	preferences := make([]map[string]interface{}, 0, len(s.supportedMethods))
	for _, methodInfo := range s.supportedMethods {
		if pref, ok := s.preferences[methodInfo.Protocol]; ok {
			preferences = append(preferences, pref.(map[string]interface{}))
		}
	}
	uniqueCiphers := make([]cipher.Info, 0)
	seen := make(map[string]struct{})
	for _, methodInfo := range s.supportedMethods {
		for _, c := range s.supportedCiphers[methodInfo.Protocol] {
			if _, ok := seen[c.Name]; ok {
				continue
			}
			seen[c.Name] = struct{}{}
			uniqueCiphers = append(uniqueCiphers, c)
		}
	}
	certs := make([]map[string]interface{}, 0, len(s.certs))
	for _, c := range s.certs {
		certs = append(certs, c.ToMap())
	}
	curves := make([]map[string]interface{}, 0, len(s.supportedCurves))
	for _, name := range s.supportedCurves {
		curves = append(curves, map[string]interface{}{
			"name":   name,
			"states": state.Empty(),
		})
	}
	protocols := make([]map[string]interface{}, 0, len(s.supportedMethods))
	for _, m := range s.supportedMethods {
		protocols = append(protocols, m.ToMap())
	}
	cipherMaps := make([]map[string]interface{}, 0, len(uniqueCiphers))
	for _, c := range uniqueCiphers {
		cipherMaps = append(cipherMaps, c.ToMap())
	}
	return map[string]interface{}{
		"certs":              certs,
		"dh":                 []interface{}{},
		"hsts":               s.hsts,
		"protocols":          protocols,
		"ciphers":            cipherMaps,
		"ciphers_preference": preferences,
		"curves":             curves,
		"curves_preference":  s.curvesPreference,
		"fallback_scsv":      s.fallbackSCSV,
	}
}

func (s *Server) States() state.Map {
	children := make([]state.Checker, 0)
	for _, c := range s.certs {
		children = append(children, c)
	}
	for _, m := range s.supportedMethods {
		children = append(children, m)
	}
	for _, methodInfo := range s.supportedMethods {
		for _, c := range s.supportedCiphers[methodInfo.Protocol] {
			children = append(children, c)
		}
	}
	checks := make([]state.Check, 0, 2)
	if s.fallbackSCSV == nil {
		checks = append(checks, state.Check{Name: "fallback_scsv", Level: state.Good, Result: nil})
	} else {
		checks = append(checks, state.Check{Name: "fallback_scsv", Level: state.Good, Result: s.fallbackSCSV == true})
	}
	if s.hsts == nil {
		checks = append(checks, state.Check{Name: "hsts", Level: state.Warning, Result: true})
	} else if age, ok := s.hsts.(int); ok && age >= longHSTS {
		checks = append(checks,
			state.Check{Name: "hsts", Level: state.Warning, Result: false},
			state.Check{Name: "hsts", Level: state.Good, Result: true},
			state.Check{Name: "hsts", Level: state.Great, Result: true},
		)
	} else {
		checks = append(checks,
			state.Check{Name: "hsts", Level: state.Warning, Result: false},
			state.Check{Name: "hsts", Level: state.Good, Result: true},
			state.Check{Name: "hsts", Level: state.Great, Result: false},
		)
	}
	base := serverChecks{checks: checks, children: children}
	return state.Collect(base)
}

func (s *Server) Grade() string {
	return grade.Calculate(s.valid, s.trusted, s.States())
}

type serverChecks struct {
	checks   []state.Check
	children []state.Checker
}

func (s serverChecks) Checks() []state.Check     { return s.checks }
func (s serverChecks) Children() []state.Checker { return s.children }

type handshakeOptions struct {
	minVersion uint16
	maxVersion uint16
	suites     []uint16
	curves     []tls.CurveID
	fallback   bool
}

func (s *Server) handshake(ctx context.Context, cfg Config, opts handshakeOptions) (*tls.ConnectionState, error) {
	dialer := &net.Dialer{Timeout: cfg.TCPTimeout}
	address := net.JoinHostPort(s.IP, strconv.Itoa(s.Port))
	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	defer rawConn.Close()

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         opts.minVersion,
		MaxVersion:         opts.maxVersion,
		CipherSuites:       opts.suites,
		CurvePreferences:   opts.curves,
		ServerName:         s.Hostname,
	}
	conn := tls.Client(rawConn, tlsConfig)
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	state := conn.ConnectionState()
	return &state, nil
}

func (s *Server) negotiatedCipher(ctx context.Context, cfg Config, proto uint16, first, second string, suites []probeSuite) (string, error) {
	ids := []uint16{
		suiteIDByOpenSSL(first, suites),
		suiteIDByOpenSSL(second, suites),
	}
	ids = filterZero(ids)
	if len(ids) == 0 {
		return "", fmt.Errorf("unknown cipher")
	}
	connState, err := s.handshake(ctx, cfg, handshakeOptions{
		minVersion: proto,
		maxVersion: proto,
		suites:     ids,
	})
	if err != nil {
		return "", err
	}
	return cipher.GoNameToOpenSSL(tls.CipherSuiteName(connState.CipherSuite)), nil
}

func suiteIDByOpenSSL(name string, suites []probeSuite) uint16 {
	for _, suite := range suites {
		if cipher.GoNameToOpenSSL(suite.name) == name {
			return suite.id
		}
	}
	return 0
}

func filterZero(ids []uint16) []uint16 {
	out := make([]uint16, 0, len(ids))
	for _, id := range ids {
		if id != 0 {
			out = append(out, id)
		}
	}
	return out
}

func suitesForVersion(suites []probeSuite, version uint16) []probeSuite {
	out := make([]probeSuite, 0)
	for _, suite := range suites {
		if suite.minVersion <= version && version <= suite.maxVersion {
			out = append(out, suite)
		}
	}
	return out
}

func suiteIDsForVersion(suites []probeSuite, version uint16) []uint16 {
	out := make([]uint16, 0)
	for _, suite := range suitesForVersion(suites, version) {
		out = append(out, suite.id)
	}
	return out
}

func versionFromName(name string) uint16 {
	switch name {
	case "TLSv1_3":
		return tls.VersionTLS13
	case "TLSv1_2":
		return tls.VersionTLS12
	case "TLSv1_1":
		return tls.VersionTLS11
	case "TLSv1":
		return tls.VersionTLS10
	default:
		return tls.VersionTLS12
	}
}
