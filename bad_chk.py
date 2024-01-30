from scapy.all import *
from netfilterqueue import NetfilterQueue
import time

def spoof_reply(packet):
    pkt = IP(packet.get_payload())
    dst=pkt[0].dst
    src=pkt[0].src
    seq = pkt[1].seq
    #seq = 22
    id = pkt[1].id
    #id = 1111
    load=pkt[2].load
    ip = IP(src=dst, dst=src)
    #icmp = ICMP(type=0, id=id, seq=seq)
    #reply = ip/icmp/load
    #reply[ICMP].chksum = 0x82e2
    send(ip/ICMP(type=0, id=id, seq=seq, chksum=0x82e2)/load)
    
if __name__=="__main__":
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, spoof_reply)
    try:
        nfqueue.run()
    except :
        print("error")
    nfqueue.unbind()
