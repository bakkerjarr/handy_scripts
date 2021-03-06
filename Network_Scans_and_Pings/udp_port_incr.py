#!/usr/bin/env python

"""Use Scapy to send a UDP header to a host n times a second while
increasing the port number. Note that checks are not made in regards
to the value of the port number.
"""

from random import randint
import datetime as dt
import sys
import time
import argparse
import signal

from scapy.all import *

__author__ = "Jarrod N. Bakker"
__status__ = "Does not work as desired."

MAX_PORTS = 65535
PORT_SRC = 1234

def signal_handler(signal, frame):
    """Catch Ctrl+C and terminate the script somewhat gracefully.
    """
    print("[!] Terminating script.")
    sys.exit(0)

def get_port_ephem():
    """Generate a random number to act as an ephemeral port. The chances of a
    collision happening should be low.

    :return - an int representing an ephemeral port.
    """
    return randint(32768, 61000)


def send_udp(host_ip4, port_dst, port_src, num):
    """Send a UDP header and print the result.

    :param host_ip4 - the host to send the header to.
    :param port_dst - the destination port number.
    :param port_src - the source port number.
    :param num - the packet in the sequence that the header belongs to.
    """
    print("Frame port number: {0}".format(port_dst))
    send(IP(dst=host_ip4)/UDP(dport=port_dst, sport=port_src),
        verbose=True)


def main(host_ip4, duration, pps, second_host):
    """'Ping' a host using UDP.

    :param host_ip4 - the host to send the UDP header to.
    :param duration - duration of the test in second.
    :param pps - packets to be sent per second.
    :param second_host - an optional second host to send to.
    """
    print("[+] Starting UDP Port Increase Scan to {0} for {1} "
          "seconds with {2} packets per second.".format(host_ip4,
                                                        duration, pps))
    wait_duration = 1/float(pps)
    signal.alarm(duration)
    if second_host == "N/A":
        for i in range(MAX_PORTS):
            send_udp(host_ip4, i, PORT_SRC, i)
            time.sleep(wait_duration)
    else:
        for i in range(MAX_PORTS):
            second_host_port = i + 500
            send_udp(host_ip4, i, PORT_SRC, i)
            send_udp(second_host, second_host_port, PORT_SRC, i)
            time.sleep(wait_duration)


if __name__ == "__main__":
    # Register a handler for catching Ctrl+c
    signal.signal(signal.SIGINT, signal_handler)

    # Process script arguments
    program_desc = "Use Scapy to send a UDP header to a host"
    host_ip4_help = "The target machine's IPv4 address."
    duration_help = "The duration of the scan (sec)."
    pps_help = "Number of frames to send per second."
    start_help = "Time to start the script at (optional)."
    second_host_help = "An optional second host to send to."
    
    parser = argparse.ArgumentParser(description=program_desc)
    parser.add_argument("host_ip4", metavar="IPv4", type=str,
                        help=host_ip4_help)
    parser.add_argument("duration", metavar="DURATION", default=0,
                        type=int, help=duration_help)
    parser.add_argument("pps", metavar="PACKETS-PER-SECOND", default=0,
                        type=int, help=pps_help)
    parser.add_argument("-s", dest="start", default="N/A",
                        help=start_help)
    parser.add_argument("-2", dest="second_host", default="N/A",
                        help=second_host_help)
    args = parser.parse_args()
    if args.start != "N/A":
        start_time = None
        try:
            start_time = dt.datetime.strptime(args.start, "%H:%M:%S")
        except ValueError:
            print("[-] Invalid time passed.")
            sys.exit(-1)
        current_time = dt.datetime.now().strftime("%H:%M:%S")
        normalised_current = dt.datetime.strptime(current_time,
                                                  "%H:%M:%S")
        wait_for = (start_time - normalised_current).seconds
        time.sleep(wait_for)
    if args.pps < 1:
        print("[-] Packets per second argument should be a whole "
              "number larger than 0.")
        sys.exit(-1)
    main(args.host_ip4, args.duration, args.pps, args.second_host)
