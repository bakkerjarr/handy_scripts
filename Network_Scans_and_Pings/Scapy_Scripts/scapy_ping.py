#!/usr/bin/env python

"""Use Scapy to ping a host using an ICMP Echo Request.
"""

from sys import exit
from time import sleep
import argparse
import signal

from scapy.all import *

__author__ = "Jarrod N. Bakker"
__status__ = "Works as desired."


def signal_handler(signal, frame):
    """Catch Ctrl+C and terminate the script somewhat gracefully.
    """
    print("[!] Terminating script.")
    exit(0)


def send_icmp_er(host_ip4, seq_num):
    """Send a ICMP echo request and print the result.

    :param host_ip4 - the host to send the ICMP Echo Requests to.
    :param seq_num - the ICMP sequence number.
    """
    resp = sr1(IP(dst=host_ip4)/ICMP(seq=seq_num), verbose=False)
    icmp_seq = int(resp.sprintf("%ICMP.seq%"), 16)
    print(resp.summary() + " icmp_seq={0}".format(icmp_seq))


def main(host_ip4, count):
    """Ping a host.

    :param host_ip4 - the host to send the ICMP Echo Requests to.
    :param count - the number of Echo Requests to send. If < 1 then don't
               stop sending Echo Requests.
    """
    print("[+] Starting ping to {0}".format(host_ip4))
    if count < 1:
        i = 1
        while True:
            send_icmp_er(host_ip4, i)
            i += 1
            sleep(1)
    else:
        print("[+] Sending {0} Echo Requests.".format(count))
        for i in range(count):
            send_icmp_er(host_ip4, i+1)
            sleep(1)

if __name__ == "__main__":
    # Register a handler for catching Ctrl+c
    signal.signal(signal.SIGINT, signal_handler)

    # Process script arguments
    program_desc = "Use Scapy to ping a host using an ICMP Echo Request"
    host_ip4_help = "The target machine's IPv4 address."
    count_help = ("The number of pings to be made. Leave blank for "
                  "there to be no upper limit (or < 1).")
    
    parser = argparse.ArgumentParser(description=program_desc)
    parser.add_argument("host_ip4", metavar="IPv4", type=str,
                        help=host_ip4_help)
    parser.add_argument("-c", dest="count", default=0, type=int,
                        help=count_help)

    args = parser.parse_args()

    main(args.host_ip4, args.count)
