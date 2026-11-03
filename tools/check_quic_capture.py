"""HTTP/3 using normal IPv4 UDP sockets, for selected-app capture validation."""
import asyncio
import json
from pathlib import Path
import socket
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.runtime/quic-libs'))
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.connection import QuicConnection
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3Connection,H3_ALPN
from aioquic.h3.events import HeadersReceived,DataReceived


class Client(QuicConnectionProtocol):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.http=H3Connection(self._quic)
        self.response=asyncio.get_running_loop().create_future()
        self.headers=[];self.body=bytearray()

    def quic_event_received(self,event):
        super().quic_event_received(event)
        for item in self.http.handle_event(event):
            if isinstance(item,HeadersReceived):self.headers.extend(item.headers)
            if isinstance(item,DataReceived):self.body.extend(item.data)
            if getattr(item,'stream_ended',False) and not self.response.done():
                self.response.set_result((dict(self.headers),self.body.decode()))


async def main():
    host='www.cloudflare.com';loop=asyncio.get_running_loop()
    address=(socket.gethostbyname(host),443)
    config=QuicConfiguration(is_client=True,alpn_protocols=H3_ALPN,server_name=host,max_datagram_size=1350)
    transport,protocol=await loop.create_datagram_endpoint(lambda:Client(QuicConnection(configuration=config)),local_addr=('0.0.0.0',0),family=socket.AF_INET)
    try:
        protocol.connect(address)
        await asyncio.wait_for(protocol.wait_connected(),12)
        stream=protocol._quic.get_next_available_stream_id()
        protocol.http.send_headers(stream,[(b':method',b'GET'),(b':scheme',b'https'),(b':authority',host.encode()),(b':path',b'/cdn-cgi/trace')],end_stream=True)
        protocol.transmit()
        headers,body=await asyncio.wait_for(protocol.response,12)
        if headers.get(b':status')!=b'200':raise RuntimeError(str(headers))
        egress=next(line[3:] for line in body.splitlines() if line.startswith('ip='))
        print(json.dumps(dict(passed=True,protocol='h3',capture='normal_ipv4_socket',datagram_size=1350,egress_ipv4=egress,bytes=len(body))))
    finally:
        protocol.close();transport.close()


if __name__=='__main__':asyncio.run(main())
