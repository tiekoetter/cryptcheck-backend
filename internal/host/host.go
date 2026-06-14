package host

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/tiekoetter/cryptcheck-backend/internal/engine"
	"github.com/tiekoetter/cryptcheck-backend/internal/state"
)

type Result struct {
	Hostname   string                 `json:"hostname"`
	IP         string                 `json:"ip,omitempty"`
	Port       int                    `json:"port"`
	Grade      string                 `json:"grade,omitempty"`
	States     map[string]interface{} `json:"states,omitempty"`
	Handshakes map[string]interface{} `json:"handshakes,omitempty"`
	Error      string                 `json:"error,omitempty"`
}

type Analyzer struct {
	Timeout time.Duration
}

func (a Analyzer) AnalyzeHTTPS(ctx context.Context, hostname string, port int) ([]Result, error) {
	ips, err := a.resolve(ctx, hostname)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses found for %s", hostname)
	}

	cfg := engine.Config{TCPTimeout: a.Timeout}
	if cfg.TCPTimeout <= 0 {
		cfg.TCPTimeout = 10 * time.Second
	}

	results := make([]Result, 0, len(ips))
	for _, ip := range ips {
		results = append(results, a.analyzeIP(ctx, hostname, ip, port, cfg))
	}
	return results, nil
}

func (a Analyzer) analyzeIP(ctx context.Context, hostname, ip string, port int, cfg engine.Config) Result {
	base := Result{Hostname: hostname, IP: ip, Port: port}
	server, err := engine.Analyze(ctx, hostname, ip, port, cfg)
	if err != nil {
		base.Error = err.Error()
		return base
	}
	server.FetchHSTS(ctx, cfg.TCPTimeout)
	base.Handshakes = server.ToMap()
	base.States = state.ExportJSON(server.States())
	base.Grade = server.Grade()
	return base
}

func (a Analyzer) resolve(ctx context.Context, hostname string) ([]string, error) {
	if parsed := net.ParseIP(hostname); parsed != nil {
		return []string{parsed.String()}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return nil, err
	}
	ips := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, addr.IP.String())
	}
	return ips, nil
}
