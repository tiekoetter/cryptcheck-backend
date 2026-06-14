package cipher

import (
	"regexp"
	"strings"

	"github.com/tiekoetter/cryptcheck-backend/internal/state"
)

type Info struct {
	Protocol string
	Name     string
}

func (c Info) Checks() []state.Check {
	return []state.Check{
		{Name: "dss", Level: state.Critical, Result: c.matchType("DSS")},
		{Name: "anonymous", Level: state.Critical, Result: c.matchType("ADH", "AECDH")},
		{Name: "null", Level: state.Critical, Result: c.matchType("NULL")},
		{Name: "export", Level: state.Critical, Result: c.matchType("EXP")},
		{Name: "des", Level: state.Critical, Result: c.matchType("DES-CBC")},
		{Name: "md5", Level: state.Critical, Result: c.matchType("MD5")},
		{Name: "sha1", Level: state.Warning, Result: c.matchType("SHA") && !c.matchType("SHA256", "SHA384")},
		{Name: "rc4", Level: state.Critical, Result: c.matchType("RC4")},
		{Name: "sweet32", Level: state.Critical, Result: c.sweet32()},
		{Name: "pfs", Level: state.Error, Result: !c.pfs()},
		{Name: "dhe", Level: state.Warning, Result: c.matchType("DHE", "EDH", "ADH")},
		{Name: "aead", Level: state.Good, Result: c.aead()},
	}
}

func (c Info) Children() []state.Checker { return nil }

func (c Info) ToMap() map[string]interface{} {
	hmacName, hmacSize := c.hmac()
	enc := c.encryption()
	out := map[string]interface{}{
		"protocol":       c.Protocol,
		"name":           c.Name,
		"key_exchange":   c.kex(),
		"authentication": c.auth(),
		"encryption":     enc,
		"states":         state.Collect(c),
	}
	if hmacName != "" {
		out["hmac"] = map[string]interface{}{"name": hmacName, "size": hmacSize}
	}
	return out
}

func (c Info) matchType(parts ...string) bool {
	for _, part := range parts {
		re := regexp.MustCompile(`(^|[-_])` + regexp.QuoteMeta(part) + `([-_]|$)`)
		if re.MatchString(c.Name) {
			return true
		}
	}
	return false
}

func (c Info) pfs() bool {
	if c.Protocol == "TLSv1_3" {
		return true
	}
	return c.matchType("DHE", "EDH", "ECDHE", "AECDH")
}

func (c Info) aead() bool {
	return c.matchType("GCM", "CCM", "CCM8") || c.matchType("CHACHA20")
}

func (c Info) sweet32() bool {
	enc := c.encryption()
	if len(enc) < 2 {
		return false
	}
	size, ok := enc[1].(int)
	return ok && size <= 64
}

func (c Info) kex() string {
	switch {
	case c.matchType("ECDHE", "AECDH", "ECDH"):
		return "ecdh"
	case c.matchType("DHE", "EDH", "ADH", "DH"):
		return "dh"
	case c.matchType("DSS"):
		return "dss"
	default:
		return "rsa"
	}
}

func (c Info) auth() interface{} {
	switch {
	case c.matchType("ECDSA"):
		return "ecdsa"
	case c.matchType("RSA"):
		return "rsa"
	case c.matchType("DSS"):
		return "dss"
	case c.matchType("ADH", "AECDH"):
		return nil
	default:
		return "rsa"
	}
}

func (c Info) encryption() []interface{} {
	mode := c.mode()
	switch {
	case c.matchType("CHACHA20"):
		return []interface{}{"chacha20", 256, "stream", mode}
	case c.matchType("AES256", "AES-256", "AES_256"):
		return []interface{}{"aes", 256, 128, mode}
	case c.matchType("AES128", "AES-128", "AES_128"):
		return []interface{}{"aes", 128, 128, mode}
	case c.matchType("3DES", "DES-CBC3"):
		return []interface{}{"3des", 112, 64, mode}
	case c.matchType("DES-CBC"):
		return []interface{}{"des", 56, 64, mode}
	case c.matchType("RC4"):
		return []interface{}{"rc4", 128, "stream", mode}
	default:
		return nil
	}
}

func (c Info) mode() interface{} {
	switch {
	case c.matchType("GCM"):
		return "gcm"
	case c.matchType("CHACHA20"):
		return "aead"
	case c.matchType("RC4"):
		return nil
	default:
		return "cbc"
	}
}

func (c Info) hmac() (string, int) {
	switch {
	case c.matchType("POLY1305"):
		return "poly1305", 128
	case c.matchType("SHA384"):
		return "sha384", 384
	case c.matchType("SHA256"):
		return "sha256", 256
	case c.matchType("SHA"):
		return "sha1", 160
	case c.matchType("MD5"):
		return "md5", 128
	default:
		return "", 0
	}
}

func GoNameToOpenSSL(name string) string {
	name = strings.TrimPrefix(name, "TLS_")
	parts := strings.SplitN(name, "_WITH_", 2)
	if len(parts) != 2 {
		return name
	}
	left := strings.ReplaceAll(parts[0], "_", "-")
	right := strings.ReplaceAll(parts[1], "_", "-")
	right = strings.ReplaceAll(right, "AES-128", "AES128")
	right = strings.ReplaceAll(right, "AES-256", "AES256")
	right = strings.ReplaceAll(right, "3DES-EDE", "3DES")
	if strings.Contains(right, "CHACHA20-POLY1305-SHA256") {
		right = strings.TrimSuffix(right, "-SHA256")
	}
	return left + "-" + right
}
