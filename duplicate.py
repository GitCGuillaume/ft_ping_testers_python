from scapy.all import *
from netfilterqueue import NetfilterQueue
import time

def spoof_reply(packet):
    pkt = IP(packet.get_payload())
    #if (pkt[2].type == 8):
    #check if the ICMP is a request

    dst=pkt[0].dst
    pkt.show2()
        #store the original packet's destination

    src=pkt[0].src
        #store the original packet's source

    seq = pkt[1].seq
        #seq = 22
        #store the original packet's sequence

    id = pkt[1].id
        #id = 1111
        #store the original packet's id

    load=pkt[2].load
        #store the original packet's load
    ip = IP(src=dst, dst=src)
    icmp = ICMP(type=0, id=id, seq=seq)
    icmp2 = ICMP(type=0, id=id, seq=seq)
    reply = ip/icmp/load
    #reply2 = ip/icmp2/load
    #nbPacketRcv > nbPacketSent = display packet forged
    reply2 = ip/icmp2/load
    send(reply)
    send(reply2)
     #   time.sleep(3)
     #   send(reply)

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
