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
      icmp = ICMP(type=3, code=0, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)
      #code 1
      icmp = ICMP(type=3, code=1, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)
      #code 2
      icmp = ICMP(type=3, code=2, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)
     #code 3
      icmp = ICMP(type=3, code=3, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)
#code 4
      icmp = ICMP(type=3, code=4, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
 #code 5
      icmp = ICMP(type=3, code=5, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)
      send(reply)
#code 6
      icmp = ICMP(type=3, code=6, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)
#code 7
      icmp = ICMP(type=3, code=7, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)
#code 8
      icmp = ICMP(type=3, code=8, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)
#code 9
      icmp = ICMP(type=3, code=9, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)
#code 10
      icmp = ICMP(type=3, code=10, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)
#code 11
      icmp = ICMP(type=3, code=11, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)
#code 12
      icmp = ICMP(type=3, code=12, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)
#code 13
      icmp = ICMP(type=3, code=13, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)
#code 14
      icmp = ICMP(type=3, code=14, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)
#code 15
      icmp = ICMP(type=3, code=15, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      send(reply)
#code 16
      icmp = ICMP(type=3, code=16, id=id, seq=seq)
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
