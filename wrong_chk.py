from scapy.all import *
from netfilterqueue import NetfilterQueue
import time

def spoof_reply(packet):
    pkt = IP(packet.get_payload())
    dst=pkt[0].dst
    pkt.show2()
    src=pkt[0].src
    seq = pkt[1].seq
    #seq = 22
    id = pkt[1].id
    #id = 1111
    load=pkt[2].load
    ip = IP(src=dst, dst=src)
    icmp = ICMP(type=0, id=id, seq=seq)
    icmp.chksum = 0x0000
    reply = ip/icmp/load
    #reply.show2()
    send(reply)
    
if __name__=="__main__":
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, spoof_reply)
    try:
        nfqueue.run()
    except :
        print("error")
    nfqueue.unbind()
#    sniff(iface="enp0s8", prn=spoof_reply, filter="icmp")
#pkts = sniff(iface="enp0s8", filter="icmp", prn=test)
