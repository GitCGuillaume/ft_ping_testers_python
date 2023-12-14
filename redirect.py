from scapy.all import *
from netfilterqueue import NetfilterQueue
import time
import copy;

def reply(packet):
    pkt = IP(packet.get_payload())
    if (pkt[1].type == 8):
      load=copy.deepcopy(pkt)
      dst=pkt[0].dst
      src=pkt[0].src
      seq = pkt[1].seq
      id = pkt[1].id
      ip = IP(src=dst, dst=src)
      #code 0
      icmp = ICMP(type=5, code=0, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)
      #code 1
      icmp = ICMP(type=5, code=1, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)
      #code 2
      icmp = ICMP(type=5, code=2, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)
      #code 3
      icmp = ICMP(type=5, code=4, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)


nfqueue = NetfilterQueue()
nfqueue.bind(1, reply)
try:
    nfqueue.run()
except :
    print("error")
nfqueue.unbind()
