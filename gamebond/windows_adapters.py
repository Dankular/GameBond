"""Read-only IP Helper adapter inventory and address/interface notifications."""
import ctypes as C
import ipaddress
import socket
import threading

U32=C.c_uint32
PTR=C.c_void_p

class SocketAddress(C.Structure):
    _fields_=[('address',PTR),('length',C.c_int)]

class Address(C.Structure):pass
Address._fields_=[('length',U32),('flags',U32),('next',C.POINTER(Address)),('socket',SocketAddress),
                 ('prefix_origin',U32),('suffix_origin',U32),('dad',U32),('valid',U32),('preferred',U32),('lease',U32),('prefix',C.c_ubyte)]

class Gateway(C.Structure):pass
Gateway._fields_=[('length',U32),('reserved',U32),('next',C.POINTER(Gateway)),('socket',SocketAddress)]

class Adapter(C.Structure):pass
Adapter._fields_=[('length',U32),('index',U32),('next',C.POINTER(Adapter)),('id',C.c_char_p),
    ('unicast',C.POINTER(Address)),('anycast',PTR),('multicast',PTR),('dns',PTR),
    ('dns_suffix',C.c_wchar_p),('description',C.c_wchar_p),('name',C.c_wchar_p),
    ('mac',C.c_ubyte*8),('mac_length',U32),('flags',U32),('mtu',U32),('kind',U32),
    ('oper_status',U32),('ipv6_index',U32),('zones',U32*16),('prefix',PTR),
    ('tx_speed',C.c_uint64),('rx_speed',C.c_uint64),('wins',PTR),('gateway',C.POINTER(Gateway))]


def _ipv4(address):
    if not address.address or address.length<8:return None
    raw=C.string_at(address.address,8)
    if int.from_bytes(raw[:2],'little')!=socket.AF_INET:return None
    value=ipaddress.IPv4Address(raw[4:8])
    return None if value.is_unspecified or value.is_link_local or value.is_loopback else str(value)


def discover_adapters():
    api=C.WinDLL('iphlpapi',use_last_error=True)
    call=api.GetAdaptersAddresses
    call.argtypes=[U32,U32,PTR,PTR,C.POINTER(U32)];call.restype=U32
    size=U32(16384)
    for _ in range(4):
        if size.value>1024*1024:raise RuntimeError('Adapter inventory exceeds its bound')
        buffer=C.create_string_buffer(size.value)
        result=call(socket.AF_INET,0x80|0x100|2|4|8,None,buffer,C.byref(size))
        if result==111:continue
        if result==232:return []
        if result:raise C.WinError(result)
        break
    else:raise RuntimeError('Adapter inventory changed repeatedly; retry')
    rows=[];current=C.cast(buffer,C.POINTER(Adapter))
    while current and len(rows)<256:
        item=current.contents;addresses=[];address=item.unicast;seen=set()
        while address and len(seen)<256:
            location=C.addressof(address.contents)
            if location in seen:break
            seen.add(location);entry=address.contents
            value=_ipv4(entry.socket)
            if value and entry.dad==4:addresses.append(value)
            address=entry.next
        gateway='';entry=item.gateway
        if entry:gateway=_ipv4(entry.contents.socket) or ''
        rows.append(dict(index=int(item.index),id=(item.id or b'').decode('ascii').lower(),
            name=item.name or '',description=item.description or '',up=item.oper_status==1,
            addresses=sorted(set(addresses)),gateway=gateway,kind=int(item.kind)))
        current=item.next
    return rows


class AdapterNotifications:
    """Callbacks only wake a worker; inventory/socket work runs outside Windows callbacks."""
    def __init__(self):
        self.changed=threading.Event();self.handles=[]
        self.api=C.WinDLL('iphlpapi',use_last_error=True)
        prototype=C.WINFUNCTYPE(None,PTR,PTR,C.c_int)
        self.callback=prototype(lambda context,row,kind:self.changed.set())
        self.api.CancelMibChangeNotify2.argtypes=[PTR];self.api.CancelMibChangeNotify2.restype=U32
        try:
            for name in ('NotifyIpInterfaceChange','NotifyUnicastIpAddressChange','NotifyRouteChange2'):
                call=getattr(self.api,name)
                call.argtypes=[C.c_ushort,prototype,PTR,C.c_ubyte,C.POINTER(PTR)];call.restype=U32
                handle=PTR();result=call(socket.AF_INET,self.callback,None,0,C.byref(handle))
                if result:raise C.WinError(result)
                self.handles.append(handle)
        except Exception:
            self.close();raise

    def close(self):
        for handle in self.handles:self.api.CancelMibChangeNotify2(handle)
        self.handles.clear();self.changed.set()
