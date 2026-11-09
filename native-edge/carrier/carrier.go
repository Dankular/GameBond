// Package carrier is the Go port of gamebond/stream_carrier.py: bounded
// authenticated datagram carriage over TCP, TLS or HTTPS CONNECT. It moves
// already encrypted GameBond packets to one fixed UDP endpoint; it is not a
// general proxy. Every mode proves possession of the session PSK, and TLS/HTTPS
// use normal CA and hostname verification.
package carrier

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

const (
	Magic     = "GBCAR01\n"
	Authority = "gamebond.invalid:443"
	MaxFrame  = 2048
	MaxHeader = 4096
)

// Mode is one of "tcp", "tls", "https".
func validMode(m string) bool { return m == "tcp" || m == "tls" || m == "https" }

func mac(key []byte, parts ...[]byte) []byte {
	h := hmac.New(sha256.New, key)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func readExact(c net.Conn, n int, deadline time.Time) ([]byte, error) {
	buf := make([]byte, n)
	if !deadline.IsZero() {
		c.SetReadDeadline(deadline)
	}
	if _, err := io.ReadFull(c, buf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, io.EOF
		}
		return nil, err
	}
	return buf, nil
}

func readHeader(c net.Conn, deadline time.Time) ([]byte, error) {
	var out []byte
	for !bytes.HasSuffix(out, []byte("\r\n\r\n")) {
		if len(out) >= MaxHeader {
			return nil, errors.New("HTTPS CONNECT header too large")
		}
		b, err := readExact(c, 1, deadline)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}

// Authenticate runs the mutual PSK proof (server=true answers the challenge).
func Authenticate(c net.Conn, key, session []byte, mode string, server bool, deadline time.Time) error {
	if len(key) != 32 || len(session) != 16 {
		return errors.New("Invalid carrier key or session")
	}
	label := []byte("gamebond-carrier-v1/" + mode)
	if deadline.IsZero() {
		deadline = time.Now().Add(3 * time.Second)
	}
	if server {
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		c.SetWriteDeadline(deadline)
		if _, err := c.Write(append([]byte(Magic), nonce...)); err != nil {
			return err
		}
		resp, err := readExact(c, 80, deadline)
		if err != nil {
			return err
		}
		identity, clientNonce, proof := resp[:16], resp[16:48], resp[48:]
		transcript := bytes.Join([][]byte{label, nonce, identity, clientNonce}, nil)
		if !hmac.Equal(identity, session) || !hmac.Equal(proof, mac(key, []byte("client/"), transcript)) {
			return errors.New("Carrier authentication rejected")
		}
		_, err = c.Write(mac(key, []byte("server/"), transcript))
		return err
	}
	challenge, err := readExact(c, 40, deadline)
	if err != nil {
		return err
	}
	if string(challenge[:8]) != Magic {
		return errors.New("Invalid carrier greeting")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	transcript := bytes.Join([][]byte{label, challenge[8:], session, nonce}, nil)
	c.SetWriteDeadline(deadline)
	out := append(append(append([]byte{}, session...), nonce...), mac(key, []byte("client/"), transcript)...)
	if _, err := c.Write(out); err != nil {
		return err
	}
	proof, err := readExact(c, 32, deadline)
	if err != nil {
		return err
	}
	if !hmac.Equal(proof, mac(key, []byte("server/"), transcript)) {
		return errors.New("Carrier server authentication rejected")
	}
	return nil
}

// DialOptions are the optional settings for Dial.
type DialOptions struct {
	Source     net.IP // local IPv4 to bind
	CAFile     string
	CAPool     *x509.CertPool // used instead of CAFile when set
	ServerName string
	Timeout    time.Duration
	// Control lets the caller pin the egress adapter (e.g. IP_UNICAST_IF).
	Control func(network, address string, c syscall.RawConn) error
	// OnConn is called with the raw TCP connection before it is used so a
	// supervisor can cancel it.
	OnConn func(net.Conn) error
}

// Dial opens an authenticated carrier connection to host:port.
func Dial(endpoint, mode string, key, session []byte, o DialOptions) (net.Conn, error) {
	if !validMode(mode) {
		return nil, errors.New("Unknown outer transport")
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil || net.ParseIP(host) == nil || net.ParseIP(host).To4() == nil {
		return nil, fmt.Errorf("invalid carrier endpoint %q", endpoint)
	}
	timeout := o.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	deadline := time.Now().Add(timeout)
	d := net.Dialer{Timeout: timeout, Control: o.Control}
	if o.Source != nil {
		d.LocalAddr = &net.TCPAddr{IP: o.Source}
	}
	raw, err := d.Dial("tcp4", endpoint)
	if err != nil {
		return nil, err
	}
	var conn net.Conn = raw
	fail := func(err error) (net.Conn, error) { conn.Close(); return nil, err }
	if o.OnConn != nil {
		if err := o.OnConn(raw); err != nil {
			return fail(err)
		}
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetWriteBuffer(16384)
	}
	if mode != "tcp" {
		pool := o.CAPool
		if pool == nil {
			if o.CAFile == "" {
				return fail(errors.New("TLS carrier requires a trusted CA file"))
			}
			pem, err := os.ReadFile(o.CAFile)
			if err != nil {
				return fail(err)
			}
			pool = x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return fail(errors.New("no certificates in CA file"))
			}
		}
		alpn := "gamebond/1"
		if mode == "https" {
			alpn = "http/1.1"
		}
		name := o.ServerName
		if name == "" {
			name = host
		}
		tconn := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: name, MinVersion: tls.VersionTLS12, NextProtos: []string{alpn}})
		raw.SetDeadline(deadline)
		if err := tconn.Handshake(); err != nil {
			return fail(fmt.Errorf("tls handshake: %w", err))
		}
		conn = tconn
		if o.OnConn != nil {
			if err := o.OnConn(conn); err != nil {
				return fail(err)
			}
		}
	}
	if mode == "https" {
		conn.SetWriteDeadline(deadline)
		if _, err := conn.Write([]byte("CONNECT " + Authority + " HTTP/1.1\r\nHost: " + Authority + "\r\n\r\n")); err != nil {
			return fail(err)
		}
		h, err := readHeader(conn, deadline)
		if err != nil {
			return fail(err)
		}
		if first, _, _ := strings.Cut(string(h), "\r\n"); first != "HTTP/1.1 200 Connection Established" {
			return fail(errors.New("HTTPS CONNECT rejected"))
		}
	}
	if err := Authenticate(conn, key, session, mode, false, deadline); err != nil {
		return fail(fmt.Errorf("carrier authentication: %w", err))
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// WriteFrame sends one length-prefixed datagram.
func WriteFrame(w io.Writer, packet []byte) error {
	if len(packet) < 1 || len(packet) > MaxFrame {
		return errors.New("Carrier datagram exceeds its bound")
	}
	buf := make([]byte, 2+len(packet))
	binary.BigEndian.PutUint16(buf, uint16(len(packet)))
	copy(buf[2:], packet)
	_, err := w.Write(buf) // one write so frames never interleave
	return err
}

// ReadFrame reads one datagram; the caller manages deadlines.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n < 1 || n > MaxFrame {
		return nil, errors.New("Invalid carrier datagram length")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Urgent mirrors Python's priority rule: byte 36 is the packet type and type 4
// is bulk; everything else (and anything short) is sent first only when long
// enough to carry a type byte.
func Urgent(packet []byte) bool { return len(packet) > 36 && packet[36] != 4 }
