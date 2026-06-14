package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"time"

	"github.com/tiekoetter/cryptcheck-backend/internal/state"
)

type Info struct {
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
	Valid       bool
	Trusted     bool
}

func (c Info) Checks() []state.Check {
	weak := weakSignature(c.Certificate)
	checks := make([]state.Check, 0, len(weak))
	for name, active := range weak {
		checks = append(checks, state.Check{Name: name, Level: state.Critical, Result: active})
	}
	return checks
}

func (c Info) Children() []state.Checker {
	return []state.Checker{KeyInfo{PublicKey: c.Certificate.PublicKey}}
}

func (c Info) ToMap() map[string]interface{} {
	chain := make([]map[string]interface{}, 0, len(c.Chain))
	for _, link := range c.Chain {
		chain = append(chain, map[string]interface{}{
			"subject":     subjectDN(link.Subject),
			"serial":      link.SerialNumber.String(),
			"issuer":      subjectDN(link.Issuer),
			"fingerprint": fingerprint(link),
			"lifetime":    lifetime(link),
		})
	}
	return map[string]interface{}{
		"subject":     subjectDN(c.Certificate.Subject),
		"serial":      c.Certificate.SerialNumber.String(),
		"issuer":      subjectDN(c.Certificate.Issuer),
		"lifetime":    lifetime(c.Certificate),
		"fingerprint": fingerprint(c.Certificate),
		"chain":       chain,
		"key":         KeyInfo{PublicKey: c.Certificate.PublicKey}.ToMap(),
		"states":      state.Collect(c),
	}
}

type KeyInfo struct {
	PublicKey interface{}
}

func (k KeyInfo) Checks() []state.Check {
	switch key := k.PublicKey.(type) {
	case *rsa.PublicKey:
		size := key.N.BitLen()
		switch {
		case size < 1024:
			return badChecks("rsa", state.Critical)
		case size < 2048:
			return badChecks("rsa", state.Error)
		default:
			return okBadChecks("rsa", state.Critical, state.Error)
		}
	case *ecdsa.PublicKey:
		size := key.Curve.Params().BitSize
		switch {
		case size < 160:
			return badChecks("ecc", state.Critical)
		case size < 192:
			return badChecks("ecc", state.Error)
		case size < 256:
			return badChecks("ecc", state.Warning)
		default:
			return okBadChecks("ecc", state.Critical, state.Error, state.Warning)
		}
	default:
		return nil
	}
}

func badChecks(name string, worst state.Level) []state.Check {
	checks := make([]state.Check, 0, len(state.Bads))
	for _, level := range state.Bads {
		active := levelIndex(level) >= levelIndex(worst)
		checks = append(checks, state.Check{Name: name, Level: level, Result: active})
	}
	return checks
}

func okBadChecks(name string, levels ...state.Level) []state.Check {
	checks := make([]state.Check, 0, len(levels))
	for _, level := range levels {
		checks = append(checks, state.Check{Name: name, Level: level, Result: false})
	}
	return checks
}

func levelIndex(level state.Level) int {
	for i, l := range state.Bads {
		if l == level {
			return i
		}
	}
	return -1
}

func (k KeyInfo) Children() []state.Checker { return nil }

func (k KeyInfo) ToMap() map[string]interface{} {
	out := map[string]interface{}{
		"states": state.Collect(k),
	}
	switch key := k.PublicKey.(type) {
	case *rsa.PublicKey:
		out["type"] = "rsa"
		out["size"] = key.N.BitLen()
		out["fingerprint"] = publicKeyFingerprint(key)
	case *ecdsa.PublicKey:
		out["type"] = "ecc"
		out["size"] = key.Curve.Params().BitSize
		out["curve"] = curveName(key)
		out["fingerprint"] = publicKeyFingerprint(key)
	case ed25519.PublicKey:
		out["type"] = "ed25519"
		out["size"] = len(key) * 8
		out["fingerprint"] = publicKeyFingerprint(key)
	}
	return out
}

func Verify(hostname string, certs []*x509.Certificate) (valid, trusted bool) {
	if len(certs) == 0 {
		return false, false
	}
	leaf := certs[0]
	if err := leaf.VerifyHostname(hostname); err != nil {
		valid = false
	} else {
		valid = true
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return valid, false
	}
	intermediates := x509.NewCertPool()
	for _, link := range certs[1:] {
		intermediates.AddCert(link)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		DNSName:       hostname,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	})
	return valid, err == nil
}

func weakSignature(cert *x509.Certificate) map[string]bool {
	algo := cert.SignatureAlgorithm.String()
	result := map[string]bool{
		"mdc2_sign": false,
		"md2_sign":  false,
		"md4_sign":  false,
		"md5_sign":  false,
		"sha_sign":  false,
		"sha1_sign": false,
	}
	lower := strings.ToLower(algo)
	switch {
	case strings.Contains(lower, "md5"):
		result["md5_sign"] = true
	case strings.Contains(lower, "md2"):
		result["md2_sign"] = true
	case strings.Contains(lower, "md4"):
		result["md4_sign"] = true
	case strings.Contains(lower, "mdc2"):
		result["mdc2_sign"] = true
	case strings.Contains(lower, "sha1") || strings.Contains(lower, "sha-1"):
		result["sha1_sign"] = true
	case strings.Contains(lower, "sha") && !strings.Contains(lower, "sha256") && !strings.Contains(lower, "sha384") && !strings.Contains(lower, "sha512"):
		result["sha_sign"] = true
	}
	return result
}

func subjectDN(name pkix.Name) string {
	parts := make([]string, 0, 6)
	for _, c := range name.Country {
		parts = append(parts, "/C="+c)
	}
	if name.Province != nil {
		for _, p := range name.Province {
			parts = append(parts, "/ST="+p)
		}
	}
	if name.Locality != nil {
		for _, l := range name.Locality {
			parts = append(parts, "/L="+l)
		}
	}
	if len(name.Organization) > 0 {
		parts = append(parts, "/O="+name.Organization[0])
	}
	if len(name.OrganizationalUnit) > 0 {
		parts = append(parts, "/OU="+name.OrganizationalUnit[0])
	}
	if len(name.CommonName) > 0 {
		parts = append(parts, "/CN="+name.CommonName)
	}
	if len(parts) == 0 {
		return name.String()
	}
	return strings.Join(parts, "")
}

func lifetime(cert *x509.Certificate) map[string]string {
	return map[string]string{
		"not_before": cert.NotBefore.UTC().Format("2006-01-02 15:04:05 MST"),
		"not_after":  cert.NotAfter.UTC().Format("2006-01-02 15:04:05 MST"),
	}
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", sum[:])
}

func Fingerprint(cert *x509.Certificate) string {
	return fingerprint(cert)
}

func publicKeyFingerprint(key interface{}) string {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return fmt.Sprintf("%x", sum[:])
}

func CertCurveName(cert *x509.Certificate) string {
	if key, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		return curveName(key)
	}
	return "prime256v1"
}

func curveName(key *ecdsa.PublicKey) string {
	switch key.Curve.Params().Name {
	case "P-256":
		return "prime256v1"
	case "P-384":
		return "secp384r1"
	case "P-521":
		return "secp521r1"
	default:
		return key.Curve.Params().Name
	}
}
