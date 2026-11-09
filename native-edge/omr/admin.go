package omr

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// This file is gamebond/omr_admin.py: a client for the OpenMPTCProuter
// server's admin API (HTTPS, default port 65500). The server certificate is
// self-signed, so it is identified by a public-key pin (base64 SHA-256 of its
// SubjectPublicKeyInfo, curl's `--pinnedpubkey sha256//...`). Credentials are
// never sent before a pin matches, a pin is never learned silently, and a
// refused login is never retried.

const maxResponse = 2 * 1024 * 1024

var (
	pinTextRe = regexp.MustCompile(`^(?:sha256//)?([A-Za-z0-9+/]{43}=)$`)
	hexKeyRe  = regexp.MustCompile(`^[0-9a-fA-F]{64}\n?$`) // Python's $ also allows one trailing newline
)

// ErrAdmin is the base error; ErrAuth (credentials/token refused, never
// retry) and ErrPin (key does not match, nothing sent) wrap it.
var (
	ErrAdmin = errors.New("omr admin")
	ErrAuth  = fmt.Errorf("%w: credentials refused", ErrAdmin)
	ErrPin   = fmt.Errorf("%w: pin mismatch", ErrAdmin)
)

func adminErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrAdmin, fmt.Sprintf(format, a...))
}

// NormalizePin accepts the pin with or without the sha256// prefix.
func NormalizePin(text string) (string, error) {
	m := pinTextRe.FindStringSubmatch(strings.TrimSpace(text))
	if m == nil {
		return "", errors.New("pin must be the base64 SHA-256 of the server public key, optionally prefixed sha256//")
	}
	return m[1], nil
}

// SPKIPin returns the pin of a DER certificate.
func SPKIPin(der []byte) (string, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

func tlsConfig() *tls.Config {
	// Chain verification is impossible (self-signed); the pin is compared
	// against the peer key before any data is sent.
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
}

func peerPin(c *tls.Conn) (string, error) {
	certs := c.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("server sent no certificate")
	}
	sum := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

// LearnPin does a TLS handshake only (no HTTP data) and returns the server's
// pin for the user to confirm.
func LearnPin(host string, port int, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	raw, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", adminErr("cannot read the server certificate from %s:%d: %v", host, port, err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(timeout))
	c := tls.Client(raw, tlsConfig())
	if err := c.Handshake(); err != nil {
		return "", adminErr("cannot read the server certificate from %s:%d: %v", host, port, err)
	}
	pin, err := peerPin(c)
	if err != nil {
		return "", adminErr("cannot read the server certificate from %s:%d: %v", host, port, err)
	}
	return pin, nil
}

// AdminClient is one admin-API session.
type AdminClient struct {
	host    string
	port    int
	timeout time.Duration
	pin     string
	token   string
}

// NewAdminClient requires a configured pin.
func NewAdminClient(host string, port int, pin string, timeout time.Duration) (*AdminClient, error) {
	if pin == "" {
		return nil, fmt.Errorf("%w: no certificate pin configured: learn it, confirm it, and save it before logging in", ErrPin)
	}
	p, err := NormalizePin(pin)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &AdminClient{host: host, port: port, timeout: timeout, pin: p}, nil
}

func (a *AdminClient) request(method, path string, body []byte, headers map[string]string) (int, []byte, error) {
	addr := net.JoinHostPort(a.host, strconv.Itoa(a.port))
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: a.timeout}
			raw, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			raw.SetDeadline(time.Now().Add(a.timeout))
			c := tls.Client(raw, tlsConfig())
			if err := c.Handshake(); err != nil {
				raw.Close()
				return nil, err
			}
			actual, err := peerPin(c)
			if err == nil && subtle.ConstantTimeCompare([]byte(actual), []byte(a.pin)) != 1 {
				err = fmt.Errorf("%w: server key %s does not match the pin; nothing was sent", ErrPin, actual)
			}
			if err != nil {
				raw.Close()
				return nil, err
			}
			return c, nil
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: a.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var rdr io.Reader
	if body != nil {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequest(method, "https://"+addr+path, rdr)
	if err != nil {
		return 0, nil, adminErr("admin API %s %s failed: %v", method, path, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, ErrPin) {
			return 0, nil, err
		}
		return 0, nil, adminErr("admin API %s %s failed: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return 0, nil, adminErr("admin API %s %s failed: %v", method, path, err)
	}
	if len(data) > maxResponse {
		return 0, nil, adminErr("admin API response is too large")
	}
	return resp.StatusCode, data, nil
}

func decodeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, adminErr("admin API returned invalid JSON")
	}
	if dec.More() {
		return nil, adminErr("admin API returned invalid JSON")
	}
	return v, nil
}

// Login makes one attempt; a refused login returns ErrAuth and must not be
// repeated automatically (the server bans an address after six failures).
func (a *AdminClient) Login(username, password string) error {
	form := url.Values{"username": {username}, "password": {password}}.Encode()
	status, data, err := a.request("POST", "/token", []byte(form), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
	if err != nil {
		return err
	}
	if status == 400 || status == 401 || status == 403 {
		return ErrAuth
	}
	if status != 200 {
		return adminErr("login failed with HTTP %d", status)
	}
	v, err := decodeJSON(data)
	if err != nil {
		return err
	}
	m, _ := v.(map[string]any)
	token, ok := m["access_token"].(string)
	if !ok || token == "" {
		return adminErr("login response had no access token")
	}
	a.token = token
	return nil
}

// Get fetches an authenticated JSON document.
func (a *AdminClient) Get(path string) (any, error) {
	if a.token == "" {
		return nil, adminErr("not logged in")
	}
	status, data, err := a.request("GET", path, nil, map[string]string{"Authorization": "Bearer " + a.token, "Accept": "application/json"})
	if err != nil {
		return nil, err
	}
	if status == 401 || status == 403 {
		a.token = ""
		return nil, fmt.Errorf("%w: the session token was refused; log in again", ErrAuth)
	}
	if status != 200 {
		return nil, adminErr("GET %s failed with HTTP %d", path, status)
	}
	return decodeJSON(data)
}

// GetConfig fetches /config.
func (a *AdminClient) GetConfig() (map[string]any, error) {
	v, err := a.Get("/config")
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, adminErr("unexpected /config response")
	}
	return m, nil
}

// Tunnel is what the Glorytun UDP client needs from /config.
type Tunnel struct {
	Key      []byte
	TunnelIP string // "" when the server uses DHCP/unspecified: keep the configured address
	Chacha   bool
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case json.Number:
		f, err := x.Float64()
		return err != nil || f != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// TunnelSettings is tunnel_settings. The `port` field is deliberately
// ignored: omr-admin fills it from the TCP tunnel's file.
func TunnelSettings(config map[string]any) (Tunnel, error) {
	g, ok := config["glorytun"].(map[string]any)
	if !ok {
		return Tunnel{}, adminErr("the server reports no Glorytun configuration")
	}
	key, ok := g["key"].(string)
	if !ok || !hexKeyRe.MatchString(key) {
		return Tunnel{}, adminErr("the server has no usable Glorytun key (is glorytun installed there?)")
	}
	raw, _ := hex.DecodeString(strings.TrimSuffix(key, "\n"))
	t := Tunnel{Key: raw, Chacha: truthy(g["chacha"])}
	var clientIP any
	if udp := g["udp"]; truthy(udp) {
		m, ok := udp.(map[string]any)
		if !ok {
			return Tunnel{}, adminErr("unexpected glorytun.udp value")
		}
		clientIP = m["client_ip"]
	}
	if a, err := ipv4(clientIP); err == nil && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback() {
		t.TunnelIP = a.String()
	}
	return t, nil
}
