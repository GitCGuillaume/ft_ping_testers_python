from scapy.all import *
from netfilterqueue import NetfilterQueue
import time

s = 0
i = 100
def spoof_reply(packet):
    global i
    global s
    pkt = IP(packet.get_payload())
    if (pkt[1].type == 8):
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
        icmp2 = ICMP(type=0, id=id, seq=i)
        i = i + 1
        reply = ip/icmp/load
        #reply2 = ip/icmp2/load
        #nbPacketRcv > nbPacketSent = display packet forged
        reply2 = ip/icmp2/load
        send(reply2)
        if s == 1 and i == 102:
            send(ip/ICMP(type=0, id=id, seq=1)/load)
        elif s == 0 and i == 102:
            print(i)
            s = 1
        elif i == 105:
            i = 100
        else:
            print("sss")
            send(reply)
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
