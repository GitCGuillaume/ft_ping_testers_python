from scapy.all import *
from netfilterqueue import NetfilterQueue
import time

def spoof_reply(packet):
    pkt = IP(packet.get_payload())
    if (pkt[1].type == 8):
        dst=pkt[0].dst
        #pkt.show2()
        src=pkt[0].src
        seq = pkt[1].seq
        #seq = 22
        id = pkt[1].id
        #id = 1111
        #load=pkt[2].load
        ip = IP(src=dst, dst=src)
        #icmp = ICMP(type=0, id=id, seq=seq)
        #reply = ip/icmp/load
        #reply[ICMP].chksum = 0x82e2
        send(ip/ICMP(type=0, id=id, seq=seq)/"123456789123132545646545645646545465456456456445465456465465465456456456456")
    
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
