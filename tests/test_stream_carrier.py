from datetime import datetime,timedelta,timezone
import ipaddress
from pathlib import Path
import secrets
import socket
import ssl
import tempfile
import threading
import time
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from gamebond.stream_carrier import CarrierRelay,open_client,send_frame,receive_frame,MAX_FRAME

def certificate(directory):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'GameBond test CA')]);now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
        .sign(key,hashes.SHA256()))
    cert_path=Path(directory)/'cert.pem';key_path=Path(directory)/'key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path,key_path)
    # This workstation injects pip's client trust-store adapter into ssl.
    # Its server wrapper wrongly requires a peer certificate with CERT_NONE.
    # Use its underlying standard-library SERVER context for the local fixture;
    # the actual TLS client still performs full CA and hostname verification.
    if type(context).__module__.endswith('truststore._api'):context=context._ctx
    return cert_path,context

class StreamCarrierTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.cert,self.context=certificate(self.directory.name)
        self.key=secrets.token_bytes(32);self.session=secrets.token_bytes(16);self.relays=[]
        self.stop=threading.Event();self.received=[]
        self.udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.udp.bind(('127.0.0.1',0));self.udp.settimeout(.1)
        def echo():
            while not self.stop.is_set():
                try:data,address=self.udp.recvfrom(65535);self.received.append(data);self.udp.sendto(data,address)
                except socket.timeout:continue
                except OSError:break
        self.worker=threading.Thread(target=echo,daemon=True);self.worker.start()

    def tearDown(self):
        for relay in self.relays:relay.close()
        self.stop.set();self.udp.close();self.worker.join(1);self.directory.cleanup()

    def relay(self,mode):
        relay=CarrierRelay(('127.0.0.1',0),self.udp.getsockname(),self.key,self.session,
                           mode=mode,context=None if mode=='tcp' else self.context).start()
        self.relays.append(relay);return relay

    def test_tcp_tls_and_https_preserve_datagram_boundaries_and_maximum_size(self):
        for mode in ('tcp','tls','https'):
            with self.subTest(mode=mode):
                relay=self.relay(mode)
                with open_client(relay.address,self.key,self.session,mode,ca_file=self.cert) as stream:
                    for packet in (b'a',secrets.token_bytes(MAX_FRAME),b'end'):
                        send_frame(stream,packet);self.assertEqual(receive_frame(stream),packet)
                self.assertEqual(relay.stats()['authenticated'],1)

    def test_wrong_key_and_session_never_reach_fixed_udp_destination(self):
        relay=self.relay('tls')
        for key,session in ((secrets.token_bytes(32),self.session),(self.key,secrets.token_bytes(16))):
            with self.assertRaises((OSError,EOFError,ValueError)):
                open_client(relay.address,key,session,'tls',ca_file=self.cert)
        self.assertEqual(self.received,[]);self.assertEqual(relay.stats().get('authenticated',0),0)

    def test_tls_rejects_untrusted_certificates_and_hostname_mismatch(self):
        relay=self.relay('tls')
        with self.assertRaises(ssl.SSLCertVerificationError):
            open_client(relay.address,self.key,self.session,'tls',ca_file=self.cert,server_name='wrong.example')
        with self.assertRaises(ValueError):open_client(relay.address,self.key,self.session,'tls')
        other=Path(self.directory.name)/'other-ca';other.mkdir();untrusted,_=certificate(other)
        with self.assertRaises(ssl.SSLCertVerificationError):
            open_client(relay.address,self.key,self.session,'tls',ca_file=untrusted)
        self.assertEqual(self.received,[])

    def test_oversized_or_zero_frames_are_rejected_without_udp_forwarding(self):
        relay=self.relay('tcp')
        for length in (0,MAX_FRAME+1):
            with open_client(relay.address,self.key,self.session,'tcp') as stream:
                stream.sendall(length.to_bytes(2,'big'))
                with self.assertRaises((EOFError,OSError)):receive_frame(stream)
        self.assertEqual(self.received,[])
