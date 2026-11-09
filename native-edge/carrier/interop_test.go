package carrier

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// repoRoot is the directory holding the gamebond Python package.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	root := filepath.Join(wd, "..", "..")
	if _, err := os.Stat(filepath.Join(root, "gamebond", "stream_carrier.py")); err != nil {
		t.Skip("python package not found")
	}
	return root
}

func pythonExe(t *testing.T) string {
	for _, n := range []string{"python", "python3", "py"} {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	t.Skip("python not installed")
	return ""
}

const pyRelay = `
import sys, socket, threading, ssl
sys.path.insert(0, sys.argv[1])
from gamebond.stream_carrier import CarrierRelay
key=bytes([7])*32; sess=bytes([9])*16
mode=sys.argv[2]
udp=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(("127.0.0.1",0))
def echo():
    while True:
        d,a=udp.recvfrom(4096); udp.sendto(b"py:"+d,a)
threading.Thread(target=echo,daemon=True).start()
ctx=None
if mode!="tcp":
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[3],sys.argv[4])
    if type(ctx).__module__.endswith("truststore._api"): ctx=ctx._ctx  # workstation injects pip truststore
r=CarrierRelay(("127.0.0.1",0),udp.getsockname(),key,sess,mode=mode,context=ctx).start()
print(r.address[1],flush=True)
sys.stdin.read()
`

// Go client against the real Python CarrierRelay in every mode.
func TestGoClientToPythonRelay(t *testing.T) {
	root := repoRoot(t)
	py := pythonExe(t)
	cert, ca := selfSigned(t)
	dir := t.TempDir()
	certPEM, keyPEM := writeCertFiles(t, dir, cert)
	script := filepath.Join(dir, "relay.py")
	os.WriteFile(script, []byte(pyRelay), 0o600)
	for _, mode := range []string{"tcp", "tls", "https"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(py, script, root, mode, certPEM, keyPEM)
			in, _ := cmd.StdinPipe()
			out, _ := cmd.StdoutPipe()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { in.Close(); cmd.Wait() }()
			line, err := bufio.NewReader(out).ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			conn, err := Dial("127.0.0.1:"+strings.TrimSpace(line), mode, testKey, testSess, DialOptions{CAFile: ca})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := WriteFrame(conn, []byte("from-go")); err != nil {
				t.Fatal(err)
			}
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			reply, err := ReadFrame(conn)
			if err != nil || string(reply) != "py:from-go" {
				t.Fatalf("reply %q %v", reply, err)
			}
		})
	}
}

const pyClient = `
import sys, socket, ssl, threading
sys.path.insert(0, sys.argv[1])
from gamebond.stream_carrier import open_client, send_frame, receive_frame
key=bytes([7])*32; sess=bytes([9])*16
mode=sys.argv[3]
c=open_client(("127.0.0.1",int(sys.argv[2])),key,sess,mode,ca_file=sys.argv[4] if mode!="tcp" else None)
c.settimeout(3)
send_frame(c,b"from-py")
print(receive_frame(c).decode(),flush=True)
`

// Real Python open_client against the Go Relay in every mode.
func TestPythonClientToGoRelay(t *testing.T) {
	root := repoRoot(t)
	py := pythonExe(t)
	cert, ca := selfSigned(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "client.py")
	os.WriteFile(script, []byte(pyClient), 0o600)
	for _, mode := range []string{"tcp", "tls", "https"} {
		t.Run(mode, func(t *testing.T) {
			up, _ := udpEcho(t)
			cfg := RelayConfig{Bind: "127.0.0.1:0", UDPPeer: up.LocalAddr().String(), Key: testKey, Session: testSess, Mode: mode, MaxClients: 2}
			if mode != "tcp" {
				cfg.TLS = tlsServerConfig(cert)
			}
			r, err := NewRelay(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			port := strings.Split(r.Addr().String(), ":")[1]
			outb, err := exec.Command(py, script, root, port, mode, ca).CombinedOutput()
			if err != nil || strings.TrimSpace(string(outb)) != "echo:from-py" {
				t.Fatalf("python client: %q %v", outb, err)
			}
		})
	}
}
