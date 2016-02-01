#!/usr/bin/env python

"""Use Scapy to send a TCP header to a host.

Kind of like pinging a device by using TCP.
"""

from random import randint
from sys import exit
from time import sleep
import argparse
import signal

from scapy.all import *

__author__ = "Jarrod N. Bakker"
__status__ = "Works as desired."

NUM_PORT_SRC = 1234
TIME_SLEEP = 1

"""
Catch Ctrl+C and terminate the script somewhat gracefully.
"""
def signal_handler(signal, frame):
    print("[!] Terminating script.")
    exit(0)

"""
Generate a random number to act as an ephemeral port. The chances of a
collision happening should be low.

:return - an int representing an ephemeral port.
"""
def get_port_ephem():
    return randint(32768, 61000)

"""
Send a TCP header and print the result.

:param host_ip4 - the host to send the header to.
:param port_dst - the destination port number.
:param port_src - the source port number.
:param num - the packet in the sequence that the header belongs to.
"""
def send_tcp(host_ip4, port_dst, port_src, num):
    resp = sr1(IP(dst=host_ip4)/TCP(dport=port_dst, sport=port_src),
               verbose=False)
    print(resp.summary() + "\t# {0}".format(num))

"""
'Ping' a host using TCP.

:param host_ip4 - the host to send the TCP header to.
:param port_dst - the TCP destination port number to connect to.
:param ephem - generate an ephemeral source port of True, otherwise use
               the same source port number.
:param count - the number of headers to send. If < 1 then don't stop
               sending TCP headers.
"""
def main(host_ip4, port_dst, ephem, count):
    print("[+] Starting TCP scan to {0}:{1}".format(host_ip4, port_dst))
    if count < 1:
        i = 1
        while True:
            if ephem:
                port_src = get_port_ephem()
            else:
                port_src = NUM_PORT_SRC
            send_tcp(host_ip4, port_dst, port_src, i)
            i += 1
            sleep(TIME_SLEEP)
    else:
        print("[+] Scanning the port {0} time/s.".format(count))
        for i in range(count):
            if ephem:
                port_src = get_port_ephem()
            else:
                port_src = NUM_PORT_SRC
            send_tcp(host_ip4, port_dst, port_src, i+1)
            sleep(TIME_SLEEP)

if __name__ == "__main__":
    # Register a handler for catching Ctrl+c
    signal.signal(signal.SIGINT, signal_handler)

    # Process script arguments
    program_desc = "Use Scapy to send a TCP header to a host"
    host_ip4_help = "The target machine's IPv4 address."
    port_dst_help = "TCP destination port to set."
    count_help = ("The number of scans to be made. Leave blank for "
                  "there to be no upper limit (or < 1).")
    ephem_help = "Set if ephemeral source port numbers are required."
    
    parser = argparse.ArgumentParser(description=program_desc)
    parser.add_argument("host_ip4", metavar="IPv4", type=str,
                        help=host_ip4_help)
    parser.add_argument("port_dst", metavar="DST_PORT", type=int,
                        help=port_dst_help)
    parser.add_argument("-c", dest="count", default=0, type=int,
                        help=count_help)
    parser.add_argument("-e", dest="ephem", action='store_true',
                        help=ephem_help)

    args = parser.parse_args()

    main(args.host_ip4, args.port_dst, args.ephem, args.count)
