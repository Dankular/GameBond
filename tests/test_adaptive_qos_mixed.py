"""Actual loopback UDP, synthetic downstream loss, simultaneous interactive/bulk."""
import json
import queue
import secrets
import socket
import struct
import threading
import time
import unittest
from gamebond.transport import Node,HEADER,STRIPED,DATA,OVERHEAD,BOND_OVERHEAD
from gamebond.policy import Classifier
from gamebond.adaptive_qos import AdaptiveQoS,profile_policies

MEDIA=struct.Struct('!cIQ')

def packet(kind,sequence):
    body=MEDIA.pack(kind,sequence,time.perf_counter_ns())+b'media'*16
    port=41000 if kind==b'C' else 41001
    udp=struct.pack('!HHHH',port,port+1000,len(body)+8,0)+body
    return struct.pack('!BBHHHBBH4s4s',0x45,0,len(udp)+20,0,0,64,17,0,b'\x0a\x4d\0\x02',b'\x01'*4)+udp

class MixedQoSTests(unittest.TestCase):
    def test_calls_and_streams_survive_measured_loss_during_bidirectional_bulk(self):
        key,session=secrets.token_bytes(32),secrets.token_bytes(16)
        options=dict(bonding_mode=True,mtu=1280+OVERHEAD+BOND_OVERHEAD,probe_interval=.05,path_timeout=.5,initial_rate_mbps=10,max_rate_mbps=10)
        server=Node(key,'server',session,[('127.0.0.1',0)],**options).start()
        client=Node(key,'client',session,[('127.0.0.1',0)]*2,server.addresses[0],**options).start()
        stop=threading.Event();workers=[];errors=[]
        nodes=(client,server);qos=[AdaptiveQoS(),AdaptiveQoS()];classifier=Classifier(profile_policies())
        received=[{b'C':{},b'S':{}},{b'C':{},b'S':{}}];bulk_count=[0,0];injected=[0,0]
        first=client.addresses[0]
        try:
            deadline=time.monotonic()+3
            while not all(p['healthy'] for p in client.stats()['paths']):
                if time.monotonic()>deadline:self.fail('Handshake timeout')
                time.sleep(.005)
            # Drop some bulk writes on each path. On one path also drop media;
            # the other path provides independent successful duplicate delivery.
            for index,node in enumerate(nodes):
                original=node._write;counts={}
                def write(data,path,index=index,original=original,counts=counts):
                    kind=HEADER.unpack_from(data)[3]
                    path_key=(path.socket_index,path.endpoint)
                    counts[path_key]=counts.get(path_key,0)+1
                    first_path=path.socket_index==0 if index==0 else path.endpoint==first
                    if (kind==STRIPED and counts[path_key]%7==0) or (kind==DATA and first_path):
                        injected[index]+=1;return True
                    return original(data,path)
                node._write=write
            def bulk(index):
                while not stop.is_set():nodes[index].send(b'B'+b'x'*1000,False,'bulk')
            def consume(index):
                while not stop.is_set():
                    try:data=nodes[index].recv(.02)
                    except queue.Empty:continue
                    if data[:1]==b'B':bulk_count[index]+=1;continue
                    if len(data)<28+MEDIA.size:continue
                    kind,number,sent=MEDIA.unpack_from(data,28)
                    if kind in received[index]:received[index][kind][number]=(time.perf_counter_ns()-sent)/1e6
            def guarded(fn,index):
                try:fn(index)
                except BaseException as exc:errors.append(repr(exc));stop.set()
            for index in range(2):
                for fn in (bulk,consume):
                    thread=threading.Thread(target=guarded,args=(fn,index),daemon=True);thread.start();workers.append(thread)
            deadline=time.monotonic()+6
            while True:
                for index,node in enumerate(nodes):qos[index].refresh(node.stats)
                if all(q.stats()['redundancy']['call']['active'] and q.stats()['redundancy']['stream']['active'] for q in qos):break
                if time.monotonic()>deadline:self.fail('Measured loss did not activate QoS: '+json.dumps([q.stats() for q in qos]))
                time.sleep(.02)
            sent=100
            for sequence in range(sent):
                for index,node in enumerate(nodes):
                    qos[index].refresh(node.stats)
                    for kind,profile in ((b'C','call'),(b'S','stream')):
                        data=packet(kind,sequence);classified=qos[index].classify(classifier.classify(data),profile)
                        urgent,replicate=qos[index].transmission(classified,len(data))
                        node.send(data,replicate,classified.info.flow,urgent=urgent)
                time.sleep(.01)
            deadline=time.monotonic()+2
            while time.monotonic()<deadline and any(len(values)<sent for direction in received for values in direction.values()):time.sleep(.01)
            self.assertEqual(errors,[])
            for index,direction in enumerate(received):
                self.assertGreater(bulk_count[index],0)
                for kind,values in direction.items():
                    self.assertEqual(len(values),sent,(index,kind,len(values)))
                    self.assertLess(sorted(values.values())[int(sent*.95)-1],100)
            print('Adaptive QoS mixed-flow evidence: '+json.dumps(dict(scope='UDP loopback synthetic loss; not a physical-link test',
                received=[{kind.decode():len(values) for kind,values in direction.items()} for direction in received],
                bulk_received=bulk_count,injected_drops=injected,qos=[q.stats() for q in qos])))
        finally:
            stop.set()
            for worker in workers:worker.join(2)
            client.close();server.close()
