// Package serveradmin is a client for the GameBond server's admin portal. The server only forwards a
// tunnel address (lan_tunnel_ips) it has been told about, so a device the client adopts must be added
// to the server's configuration; this package makes that change through the portal's own API, which
// validates the configuration before writing it. A change only takes effect once the server restarts.
package serveradmin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// MaxTunnelIPs is how many device addresses the server accepts.
const MaxTunnelIPs = 32

// Client talks to one portal. It logs in on first use and again when the session has expired.
type Client struct {
	// BaseURL is the portal's address, for example https://203.0.113.5:8443.
	BaseURL  string
	Password string
	// PinSHA256 is the hex SHA-256 of the portal certificate (as shown by the browser). The portal's
	// certificate is normally self-signed, so a pin is how the client knows it is talking to the
	// server; with no pin the certificate must verify against the system roots.
	PinSHA256 string
	HTTP      *http.Client

	csrf string
	mu   sync.Mutex // Security calls share one session, so they run one at a time
}

// NewClient builds a client; the address must be an https URL.
func NewClient(baseURL, password, pin string) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("serveradmin: the portal address must be an https URL")
	}
	pin = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(pin), ":", ""))
	if pin != "" {
		if b, err := hex.DecodeString(pin); err != nil || len(b) != sha256.Size {
			return nil, errors.New("serveradmin: the certificate pin must be a SHA-256 fingerprint in hex")
		}
	}
	if password == "" {
		return nil, errors.New("serveradmin: no password")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if pin != "" {
		tc.InsecureSkipVerify = true // replaced by the pin check below; the chain is not what is trusted
		tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("serveradmin: the portal presented no certificate")
			}
			sum := sha256.Sum256(raw[0])
			if hex.EncodeToString(sum[:]) != pin {
				return errors.New("serveradmin: the portal certificate does not match the pinned fingerprint")
			}
			return nil
		}
	}
	jar, _ := cookiejar.New(nil)
	return &Client{BaseURL: strings.TrimSuffix(baseURL, "/"), Password: password, PinSHA256: pin,
		HTTP: &http.Client{Timeout: 20 * time.Second, Jar: jar, Transport: &http.Transport{TLSClientConfig: tc, DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// APIError is a refusal from the portal.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("server admin: %s (HTTP %d)", e.Message, e.Status)
	}
	return fmt.Sprintf("server admin: HTTP %d", e.Status)
}

func (c *Client) do(ctx context.Context, method, path string, body any) (int, map[string]any, http.Header, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, nil, err
		}
		rd = bytes.NewReader(b)
	} else if method == http.MethodPost {
		rd = bytes.NewReader([]byte("{}"))
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("server admin %s: %w", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, resp.Header, nil
}

func apiError(status int, out map[string]any) error {
	msg, _ := out["error"].(string)
	return &APIError{Status: status, Message: msg}
}

// Login starts a session. The password is never put in an error.
func (c *Client) Login(ctx context.Context) error {
	c.csrf = ""
	status, out, hdr, err := c.do(ctx, http.MethodPost, "/api/login", map[string]any{"password": c.Password})
	if err != nil {
		return err
	}
	if status != 200 {
		return apiError(status, out)
	}
	csrf, _ := out["csrf"].(string)
	started := false
	for _, line := range hdr.Values("Set-Cookie") {
		started = started || strings.HasPrefix(line, "gb_session=")
	}
	if csrf == "" || !started {
		return errors.New("server admin: the portal did not start a session")
	}
	c.csrf = csrf
	return nil
}

func (c *Client) session(ctx context.Context) error {
	if c.csrf != "" {
		return nil
	}
	return c.Login(ctx)
}

// call runs an authenticated request, logging in again once if the session has expired.
func (c *Client) call(ctx context.Context, method, path string, body any) (int, map[string]any, error) {
	for attempt := 0; ; attempt++ {
		if err := c.session(ctx); err != nil {
			return 0, nil, err
		}
		status, out, _, err := c.do(ctx, method, path, body)
		if err != nil {
			return 0, nil, err
		}
		if status == 401 && attempt == 0 {
			c.csrf = ""
			continue
		}
		return status, out, nil
	}
}

// Config reads the server's configuration text.
func (c *Client) Config(ctx context.Context) (string, error) {
	status, out, err := c.call(ctx, http.MethodGet, "/api/config", nil)
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", apiError(status, out)
	}
	if e, ok := out["error"].(string); ok && e != "" {
		return "", errors.New("server admin: " + e)
	}
	text, _ := out["text"].(string)
	if text == "" {
		return "", errors.New("server admin: the portal returned an empty configuration")
	}
	return text, nil
}

// Validate asks the portal to check a candidate configuration without writing it.
func (c *Client) Validate(ctx context.Context, text string) error {
	status, out, err := c.call(ctx, http.MethodPost, "/api/config/validate", map[string]any{"text": text})
	if err != nil {
		return err
	}
	if status != 200 {
		return apiError(status, out)
	}
	if ok, _ := out["ok"].(bool); !ok {
		msg, _ := out["error"].(string)
		return errors.New("server admin: the server rejected the configuration: " + msg)
	}
	return nil
}

// Apply writes a configuration (the portal validates it first). It does not restart the server.
func (c *Client) Apply(ctx context.Context, text string) error {
	status, out, err := c.call(ctx, http.MethodPost, "/api/config", map[string]any{"text": text})
	if err != nil {
		return err
	}
	if status != 200 {
		return apiError(status, out)
	}
	return nil
}

// Restart asks the server process to restart; every device loses connectivity until it is back.
func (c *Client) Restart(ctx context.Context) error {
	status, out, err := c.call(ctx, http.MethodPost, "/api/restart", map[string]any{"confirm": true})
	if err != nil {
		return err
	}
	if status != 202 && status != 200 {
		return apiError(status, out)
	}
	return nil
}

// securityPaths are the portal's security endpoints; Security refuses anything else.
var securityPaths = map[string]string{
	"/api/security":         "GET POST",
	"/api/security/catalog": "GET",
	"/api/security/action":  "POST",
}

// Security calls one of the portal's security endpoints and returns its status and JSON body untouched, so the
// dashboard can pass the portal's own wording (for example nftables' complaint) to the person who made the change.
func (c *Client) Security(ctx context.Context, method, path string, body any) (int, map[string]any, error) {
	if !strings.Contains(securityPaths[path], method) || method == "" {
		return 0, nil, fmt.Errorf("server admin: %s %s is not a security endpoint", method, path)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.call(ctx, method, path, body)
}

// TunnelIPs lists the lan_tunnel_ips of a configuration text.
func TunnelIPs(text string) ([]string, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		return nil, fmt.Errorf("server configuration is not valid JSON: %w", err)
	}
	raw, ok := doc["lan_tunnel_ips"]
	if !ok || string(bytes.TrimSpace(raw)) == "null" {
		return nil, nil
	}
	var ips []string
	if err := json.Unmarshal(raw, &ips); err != nil {
		return nil, errors.New("server configuration: lan_tunnel_ips is not a list of addresses")
	}
	return ips, nil
}

// ValidDeviceIP reports whether the server accepts ip as a device address (10.77.0.3 to 10.77.0.254).
func ValidDeviceIP(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() || a.String() != ip {
		return false
	}
	b := a.As4()
	return b[0] == 10 && b[1] == 77 && b[2] == 0 && b[3] >= 3 && b[3] <= 254
}

// WithTunnelIPs returns the configuration text with add merged into lan_tunnel_ips. Every other setting keeps
// its value exactly (numbers are not re-parsed), but the file is re-indented and its keys end up sorted.
// changed is false, and the text is returned untouched, when nothing was missing.
func WithTunnelIPs(text string, add []string) (out string, changed bool, err error) {
	have, err := TunnelIPs(text)
	if err != nil {
		return "", false, err
	}
	seen := map[string]bool{}
	for _, ip := range have {
		seen[ip] = true
	}
	merged := append([]string(nil), have...)
	for _, ip := range add {
		if !ValidDeviceIP(ip) {
			return "", false, fmt.Errorf("%q is not a usable device address (10.77.0.3 to 10.77.0.254)", ip)
		}
		if !seen[ip] {
			seen[ip] = true
			merged = append(merged, ip)
			changed = true
		}
	}
	if !changed {
		return text, false, nil
	}
	if len(merged) > MaxTunnelIPs {
		return "", false, fmt.Errorf("the server accepts at most %d device addresses", MaxTunnelIPs)
	}
	sort.Slice(merged, func(i, j int) bool { return lastOctet(merged[i]) < lastOctet(merged[j]) })
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		return "", false, err
	}
	list, _ := json.Marshal(merged)
	doc["lan_tunnel_ips"] = list
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", false, err
	}
	return string(b) + "\n", true, nil
}

func lastOctet(ip string) int {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return 0
	}
	return int(a.As4()[3])
}

// EnsureTunnelIPs makes sure the server's configuration lists ips, validating before it writes. It reports
// whether the configuration changed; the server must then be restarted for it to apply.
func (c *Client) EnsureTunnelIPs(ctx context.Context, ips []string) (changed bool, err error) {
	text, err := c.Config(ctx)
	if err != nil {
		return false, err
	}
	next, changed, err := WithTunnelIPs(text, ips)
	if err != nil || !changed {
		return false, err
	}
	if err := c.Validate(ctx, next); err != nil {
		return false, err
	}
	if err := c.Apply(ctx, next); err != nil {
		return false, err
	}
	return true, nil
}

// IsLoopbackURL reports whether the portal address is on this machine.
func IsLoopbackURL(base string) bool {
	u, err := url.Parse(base)
	if err != nil {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback()
}
