package method

import "github.com/tiekoetter/cryptcheck-backend/internal/state"

type Info struct {
	Protocol string
}

func (m Info) Checks() []state.Check {
	return []state.Check{
		{Name: "sslv2", Level: state.Critical, Result: m.Protocol == "SSLv2"},
		{Name: "sslv3", Level: state.Critical, Result: m.Protocol == "SSLv3"},
		{Name: "tlsv1_0", Level: state.Error, Result: m.Protocol == "TLSv1"},
		{Name: "tlsv1_1", Level: state.Error, Result: m.Protocol == "TLSv1_1"},
	}
}

func (m Info) Children() []state.Checker { return nil }

func (m Info) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"protocol": m.Protocol,
		"states":   state.Collect(m),
	}
}

var Order = []string{"TLSv1_3", "TLSv1_2", "TLSv1_1", "TLSv1", "SSLv3", "SSLv2"}

func VersionName(version uint16) string {
	switch version {
	case 0x0304:
		return "TLSv1_3"
	case 0x0303:
		return "TLSv1_2"
	case 0x0302:
		return "TLSv1_1"
	case 0x0301:
		return "TLSv1"
	case 0x0300:
		return "SSLv3"
	default:
		return ""
	}
}
