package carrier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var (
	testKey  = bytes.Repeat([]byte{7}, 32)
	testSess = bytes.Repeat([]byte{9}, 16)
)

func selfSigned(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gb"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, ca
}

func udpEcho(t *testing.T) (*net.UDPConn, chan []byte) {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan []byte, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			got <- append([]byte(nil), buf[:n]...)
			c.WriteToUDP(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	t.Cleanup(func() { c.Close() })
	return c, got
}

func TestRelayRoundTripAllModes(t *testing.T) {
	cert, ca := selfSigned(t)
	for _, mode := range []string{"tcp", "tls", "https"} {
		t.Run(mode, func(t *testing.T) {
			up, got := udpEcho(t)
			cfg := RelayConfig{Bind: "127.0.0.1:0", UDPPeer: up.LocalAddr().String(), Key: testKey, Session: testSess, Mode: mode, MaxClients: 4}
			if mode != "tcp" {
				cfg.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
			}
			r, err := NewRelay(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			conn, err := Dial(r.Addr().String(), mode, testKey, testSess, DialOptions{CAFile: ca})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := WriteFrame(conn, []byte("hello-"+mode)); err != nil {
				t.Fatal(err)
			}
			select {
			case p := <-got:
				if string(p) != "hello-"+mode {
					t.Fatalf("upstream got %q", p)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("no upstream datagram")
			}
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			reply, err := ReadFrame(conn)
			if err != nil || string(reply) != "echo:hello-"+mode {
				t.Fatalf("reply %q %v", reply, err)
			}
			st, _ := r.Stats()
			if st["authenticated"] != 1 || st["up_datagrams"] != 1 {
				t.Fatalf("stats %v", st)
			}
		})
	}
}

func TestAuthRejections(t *testing.T) {
	up, _ := udpEcho(t)
	r, err := NewRelay(RelayConfig{Bind: "127.0.0.1:0", UDPPeer: up.LocalAddr().String(), Key: testKey, Session: testSess, Mode: "tcp", MaxClients: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := Dial(r.Addr().String(), "tcp", bytes.Repeat([]byte{8}, 32), testSess, DialOptions{}); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err := Dial(r.Addr().String(), "tcp", testKey, bytes.Repeat([]byte{1}, 16), DialOptions{}); err == nil {
		t.Fatal("wrong session accepted")
	}
	if _, err := Dial(r.Addr().String(), "tcp", testKey[:5], testSess, DialOptions{}); err == nil {
		t.Fatal("short key accepted")
	}
	time.Sleep(100 * time.Millisecond)
	st, _ := r.Stats()
	if st["authenticated"] != 0 || st["rejected_or_closed"] < 2 {
		t.Fatalf("stats %v", st)
	}
	// A TLS client against a missing CA must be refused before authentication.
	if _, err := Dial(r.Addr().String(), "tls", testKey, testSess, DialOptions{}); err == nil {
		t.Fatal("tls without CA accepted")
	}
}

func TestHTTPSRelayRejectsWrongConnect(t *testing.T) {
	cert, ca := selfSigned(t)
	up, _ := udpEcho(t)
	r, err := NewRelay(RelayConfig{Bind: "127.0.0.1:0", UDPPeer: up.LocalAddr().String(), Key: testKey, Session: testSess, Mode: "https", MaxClients: 2, TLS: &tls.Config{Certificates: []tls.Certificate{cert}}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	pool := x509.NewCertPool()
	pem, _ := os.ReadFile(ca)
	pool.AppendCertsFromPEM(pem)
	c, err := tls.Dial("tcp", r.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n"))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	if n, _ := c.Read(buf); n != 0 {
		t.Fatalf("relay answered a foreign CONNECT: %q", buf[:n])
	}
}

func TestFrameBounds(t *testing.T) {
	var b bytes.Buffer
	if WriteFrame(&b, nil) == nil || WriteFrame(&b, make([]byte, MaxFrame+1)) == nil {
		t.Fatal("bad sizes accepted")
	}
	WriteFrame(&b, []byte{1, 2, 3})
	if p, err := ReadFrame(&b); err != nil || !bytes.Equal(p, []byte{1, 2, 3}) {
		t.Fatalf("%v %v", p, err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0})); err == nil {
		t.Fatal("zero length accepted")
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0xff, 0xff})); err == nil {
		t.Fatal("oversize length accepted")
	}
}

func TestUrgent(t *testing.T) {
	p := make([]byte, 40)
	if !Urgent(p) {
		t.Fatal("type 0 should be urgent")
	}
	p[36] = 4
	if Urgent(p) || Urgent(make([]byte, 36)) {
		t.Fatal("bulk/short must not be urgent")
	}
}

func TestSettingsValidation(t *testing.T) {
	ok := StreamEndpoint{Mode: "tcp", Port: 443}
	bad := []Settings{
		{},
		DefaultSettings(StreamEndpoint{Mode: "tls", Port: 443}),
		DefaultSettings(StreamEndpoint{Mode: "udp", Port: 443}),
		DefaultSettings(StreamEndpoint{Mode: "tcp", Port: 0}),
		DefaultSettings(ok, ok),
		DefaultSettings(ok, StreamEndpoint{Mode: "tcp", Port: 80}, StreamEndpoint{Mode: "tcp", Port: 81}, StreamEndpoint{Mode: "tcp", Port: 82}),
	}
	for i, s := range bad {
		if s.Validate() == nil {
			t.Errorf("bad settings %d accepted", i)
		}
	}
	s := DefaultSettings(ok)
	s.FallbackAfter = .05
	if s.Validate() == nil {
		t.Error("tiny timer accepted")
	}
	s = DefaultSettings(ok)
	s.QueuePackets = 129
	if s.Validate() == nil {
		t.Error("big queue accepted")
	}
	if err := DefaultSettings(ok).Validate(); err != nil {
		t.Error(err)
	}
}

func TestQueuePriorityAndBound(t *testing.T) {
	q := NewQueue(3)
	q.Put([]byte("b1"), false)
	q.Put([]byte("u1"), true)
	q.Put([]byte("b2"), false)
	if q.Put([]byte("x"), true) {
		t.Fatal("over-limit accepted")
	}
	var order []string
	for {
		p, ok := q.Get()
		if !ok {
			break
		}
		order = append(order, string(p))
	}
	if len(order) != 3 || order[0] != "u1" || order[1] != "b1" || order[2] != "b2" {
		t.Fatalf("order %v", order)
	}
}

// The socket starts on UDP, falls back to the stream after the UDP path goes
// silent, carries both directions, then returns to UDP.
func TestSocketFallbackAndRecovery(t *testing.T) {
	up, got := udpEcho(t) // the "server" UDP endpoint
	peer := up.LocalAddr().(*net.UDPAddr)
	r, err := NewRelay(RelayConfig{Bind: "127.0.0.1:0", UDPPeer: peer.String(), Key: testKey, Session: testSess, Mode: "tcp", MaxClients: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	port := r.Addr().(*net.TCPAddr).Port
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	set := DefaultSettings(StreamEndpoint{Mode: "tcp", Port: port})
	set.FallbackAfter = .1
	s, err := NewSocket(local, peer, testKey, testSess, set, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.Send([]byte("udp-1")); err != nil {
		t.Fatal(err)
	}
	if p := <-got; string(p) != "udp-1" {
		t.Fatalf("got %q", p)
	}
	rv := <-s.Recv()
	if rv.Transport != "udp" || string(rv.Packet) != "echo:udp-1" {
		t.Fatalf("%+v", rv)
	}
	s.NoteAuthenticated(rv)

	time.Sleep(150 * time.Millisecond)
	s.Tick(time.Now())
	deadline := time.Now().Add(3 * time.Second)
	for !s.Stats().Ready && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	st := s.Stats()
	if !st.Ready || st.Mode != "tcp" || st.Counters["connections"] != 1 {
		t.Fatalf("no fallback: %+v", st)
	}
	if err := s.Send([]byte("stream-1")); err != nil {
		t.Fatal(err)
	}
	if p := <-got; string(p) != "stream-1" {
		t.Fatalf("got %q", p)
	}
	rv = <-s.Recv()
	if rv.Transport != "tcp" || string(rv.Packet) != "echo:stream-1" {
		t.Fatalf("%+v", rv)
	}
	if s.Stats().PeerConfirmed {
		t.Fatal("confirmed before authentication")
	}
	s.NoteAuthenticated(rv)
	if !s.Stats().PeerConfirmed {
		t.Fatal("not confirmed after authentication")
	}

	s.ReturnToUDP()
	if st := s.Stats(); st.Mode != "udp" || st.Ready || st.Counters["udp_recoveries"] != 1 {
		t.Fatalf("%+v", st)
	}
	if err := s.Send([]byte("udp-2")); err != nil {
		t.Fatal(err)
	}
	if p := <-got; string(p) != "udp-2" {
		t.Fatalf("got %q", p)
	}
}

func TestSocketReconnectingBlocksSend(t *testing.T) {
	up, _ := udpEcho(t)
	peer := up.LocalAddr().(*net.UDPAddr)
	local, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	set := DefaultSettings(StreamEndpoint{Mode: "tcp", Port: 1}) // nothing listens
	set.FallbackAfter = .1
	s, err := NewSocket(local, peer, testKey, testSess, set, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	time.Sleep(150 * time.Millisecond)
	s.Tick(time.Now())
	deadline := time.Now().Add(3 * time.Second)
	for s.Stats().Counters["connection_errors"] == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Stats().Counters["connection_errors"] == 0 {
		t.Fatal("no connection error recorded")
	}
	// Mode only changes after a successful connection, so UDP sends still work.
	if err := s.Send([]byte("x")); err != nil {
		t.Fatal(err)
	}
}

func tlsServerConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

func writeCertFiles(t *testing.T, dir string, cert tls.Certificate) (string, string) {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	c, k := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600)
	os.WriteFile(k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	return c, k
}

// An impostor relay that answers the challenge with a bad server proof must be refused.
func TestClientRejectsBadServerProof(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write(append([]byte(Magic), make([]byte, 32)...))
		buf := make([]byte, 80)
		c.Read(buf)
		c.Write(make([]byte, 32)) // not the HMAC
	}()
	if _, err := Dial(ln.Addr().String(), "tcp", testKey, testSess, DialOptions{}); err == nil {
		t.Fatal("bad server proof accepted")
	}
}
