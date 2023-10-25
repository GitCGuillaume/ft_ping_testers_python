from scapy.all import *
from netfilterqueue import NetfilterQueue
import time

def reply(packet):
    pkt = IP(packet.get_payload())
    if (pkt[1].type == 8):
      dst=pkt[0].dst
      src=pkt[0].src
      seq = pkt[1].seq
      id = pkt[1].id
      load=pkt[2].load
      ip = IP(src=dst, dst=src)
      icmp = ICMP(type=0, id=id, seq=seq)
      reply = ip/icmp/load
      reply.show2()
      time.sleep(3)
      send(reply)

nfqueue = NetfilterQueue()
nfqueue.bind(1, reply)
try:
    nfqueue.run()
except :
    print("error")
nfqueue.unbind()