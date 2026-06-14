package engine

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type httpClient struct {
	timeout time.Duration
}

func (c httpClient) headHSTS(ctx context.Context, url string) (int, bool) {
	client := &http.Client{
		Timeout: c.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // intentional
				MinVersion:         tls.VersionTLS12,
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return 0, false
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	header := resp.Header.Get("Strict-Transport-Security")
	if header == "" {
		return 0, false
	}
	parts := strings.Split(header, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "max-age=") {
			value := strings.TrimPrefix(part, "max-age=")
			value = strings.TrimPrefix(value, "Max-Age=")
			age, err := strconv.Atoi(value)
			if err != nil {
				return 0, false
			}
			return age, true
		}
	}
	return 0, false
}
