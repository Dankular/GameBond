import datetime
import http.server
import json
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from gamebond.omr_admin import (OmrAdmin, OmrAdminError, OmrAuthError, OmrPinError, learn_pin, normalize_pin, spki_pin,
                                tunnel_settings)

KEY_HEX = "AB" * 32


def self_signed(directory: Path, name="omr"):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30)).sign(key, hashes.SHA256()))
    cert_path, key_path = directory / f"{name}.pem", directory / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


class FakeOmrAdmin:
    """Mimics omr-admin's /token and /config as read from omradmin.py."""

    def __init__(self, directory: Path, config=None):
        self.cert, self.key = self_signed(directory)
        self.requests, self.logins, self.config = [], [], config
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, status, payload):
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                outer.requests.append(("POST", self.path))
                length = int(self.headers.get("Content-Length", 0))
                form = urllib.parse.parse_qs(self.rfile.read(length).decode())
                if self.path == "/token":
                    outer.logins.append((form.get("username", [""])[0], form.get("password", [""])[0]))
                    if form.get("username") == ["openmptcprouter"] and form.get("password") == ["s3cret"]:
                        return self.reply(200, {"access_token": "tok-123", "token_type": "bearer"})
                    return self.reply(400, {"detail": "Incorrect username or password"})
                self.reply(404, {})

            def do_GET(self):
                outer.requests.append(("GET", self.path))
                if self.path == "/config":
                    if self.headers.get("Authorization") != "Bearer tok-123":
                        return self.reply(403, {"detail": "Could not validate credentials"})
                    return self.reply(200, outer.config if outer.config is not None else {
                        "glorytun": {"key": KEY_HEX, "udp": {"host_ip": "10.255.254.1", "client_ip": "10.255.254.2"},
                                     "tcp": {"host_ip": "10.255.255.1", "client_ip": "10.255.255.2"}, "port": "5000", "chacha": True}})
                self.reply(404, {})

        class Quiet(http.server.ThreadingHTTPServer):
            def handle_error(self, request, client_address):
                pass                          # handshakes aborted on purpose (pin tests) are not errors here

        self.server = Quiet(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class AdminTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = Path(directory.name)
        self.server = FakeOmrAdmin(self.dir)
        self.addCleanup(self.server.close)
        self.pin = learn_pin("127.0.0.1", self.server.port)

    def client(self, pin=None):
        return OmrAdmin("127.0.0.1", self.server.port, pin=pin or self.pin, timeout=5)

    @unittest.skipUnless(shutil.which("openssl"), "needs the openssl command line")
    def test_pin_matches_the_documented_curl_recipe(self):
        # curl --pinnedpubkey recipe: SPKI DER -> SHA-256 -> base64, computed here by openssl itself.
        pubkey = subprocess.run(["openssl", "x509", "-in", str(self.server.cert), "-pubkey", "-noout"], capture_output=True, check=True).stdout
        der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"], input=pubkey, capture_output=True, check=True).stdout
        digest = subprocess.run(["openssl", "dgst", "-sha256", "-binary"], input=der, capture_output=True, check=True).stdout
        expected = subprocess.run(["openssl", "enc", "-base64"], input=digest, capture_output=True, check=True).stdout.decode().strip()
        self.assertEqual(self.pin, expected)

    def test_learning_the_pin_sends_no_http_data(self):
        self.assertEqual(self.server.requests, [])

    def test_login_and_config_yield_the_tunnel_settings(self):
        admin = self.client("sha256//" + self.pin)
        admin.login("openmptcprouter", "s3cret")
        settings = tunnel_settings(admin.get_config())
        self.assertEqual((settings["key"], settings["tunnel_ip"], settings["chacha"]), (bytes.fromhex(KEY_HEX), "10.255.254.2", True))
        self.assertEqual(self.server.requests, [("POST", "/token"), ("GET", "/config")])

    def test_a_wrong_key_aborts_before_any_data_and_credentials_are_never_sent(self):
        other = FakeOmrAdmin(self.dir)                                   # a different server key on the same port range
        self.addCleanup(other.close)
        impostor = OmrAdmin("127.0.0.1", other.port, pin=self.pin, timeout=5)
        with self.assertRaises(OmrPinError):
            impostor.login("openmptcprouter", "s3cret")
        self.assertEqual((other.requests, other.logins), ([], []))

    def test_no_pin_means_no_login(self):
        with self.assertRaises(OmrPinError):
            OmrAdmin("127.0.0.1", self.server.port, pin="")
        with self.assertRaises(ValueError):
            normalize_pin("not-a-pin")

    def test_bad_credentials_fail_once_with_a_distinct_error_and_are_not_retried(self):
        admin = self.client()
        with self.assertRaises(OmrAuthError):
            admin.login("openmptcprouter", "wrong")
        self.assertEqual(len(self.server.logins), 1)                      # one attempt only: the server bans after six
        with self.assertRaises(OmrAdminError):
            admin.get_config()                                            # and no token was stored

    def test_expired_token_is_reported_and_cleared(self):
        admin = self.client()
        admin.login("openmptcprouter", "s3cret")
        admin.token = "stale"
        with self.assertRaises(OmrAuthError):
            admin.get_config()
        self.assertEqual(admin.token, "")

    def test_unreachable_server_is_an_admin_error_not_a_crash(self):
        with self.assertRaises(OmrAdminError):
            OmrAdmin("127.0.0.1", 1, pin=self.pin, timeout=1).login("a", "b")
        with self.assertRaises(OmrAdminError):
            learn_pin("127.0.0.1", 1, timeout=1)

    def test_tunnel_settings_rejects_missing_or_malformed_data_and_ignores_dhcp_addresses(self):
        for bad in ({}, {"glorytun": {}}, {"glorytun": {"key": "zz"}}, {"glorytun": {"key": "AB" * 31}}):
            with self.assertRaises(OmrAdminError):
                tunnel_settings(bad)
        dhcp = tunnel_settings({"glorytun": {"key": KEY_HEX, "udp": {"client_ip": "dhcp"}}})
        self.assertIsNone(dhcp["tunnel_ip"])
        self.assertFalse(dhcp["chacha"])

    def test_spki_pin_survives_certificate_renewal_with_the_same_key(self):
        cert = x509.load_pem_x509_certificate(self.server.cert.read_bytes())
        key = serialization.load_pem_private_key(self.server.key.read_bytes(), None)
        now = cert.not_valid_before_utc
        renewed = (x509.CertificateBuilder().subject_name(cert.subject).issuer_name(cert.issuer).public_key(cert.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=90))
                   .sign(key, hashes.SHA256()))
        self.assertNotEqual(cert.fingerprint(hashes.SHA256()), renewed.fingerprint(hashes.SHA256()))
        self.assertEqual(spki_pin(cert.public_bytes(serialization.Encoding.DER)), spki_pin(renewed.public_bytes(serialization.Encoding.DER)))


if __name__ == "__main__":
    unittest.main()
