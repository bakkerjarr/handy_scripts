#!/usr/bin/env python

from sys import exit
import argparse
import signal

import nmap

__author__ = "Jarrod N. Bakker"
__status__ = "Untested."


class TCPNULLScan:
    """Use Nmap to port scan a host. A TCP NULL scan is used.
    """

    _NMAP_FLAGS = "-sN"

    def __init__(self, host, ports):
        """Initial fields and handlers.

        :param host: IPv4 address of target host.
        :param ports: Port numbers to scan.
        """
        self._host = host
        self._ports = ports
        # Register a handler for catching Ctrl+c
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, signal, frame):
        """Catch Ctrl+C and terminate the script somewhat gracefully.
        """
        print("[!] Terminating script.")
        exit(0)

    def scan_port(self, host, port):
        """Scan a single port on a host,

        :param host: IPv4 address of target host.
        :param port: Port number to scan as an int.
        :return: The result of the scan as a string.
        """
        scanner = nmap.PortScanner()
        scanner.scan(host, port, self._NMAP_FLAGS)
        return scanner[host]["tcp"][int(port)]["state"]

    def start_scan(self):
        """Start the TCP NULL scan.
        """
        print "[?] Starting TCP NULL scan on host {0}".format(self._host)
        for port in self._ports:
            result = self.scan_port(self._host, port)
            print("[*] {0} tcp/{1} {2}".format(self._host, port, result))
        print "[+] Scan complete."

if __name__ == "__main__":
    # TODO Add command line argument checking.
    # Process CLI arguments
    program_desc = "Use Nmap to perform a TCP NULL Scan on a host."
    host_ip4_help = "The target machine's IPv4 address."
    ports_help = "Target port numbers separated by spaces."
    port_range_help = "From the port numbers provides, scan the range."

    parser = argparse.ArgumentParser(description=program_desc)
    parser.add_argument("host_ip4", metavar="IPv4", type=str,
                        help=host_ip4_help)
    parser.add_argument("ports", metavar="PORTS", type=str,
                        help=ports_help, nargs="+")
    parser.add_argument("-r", dest="port_range", action="store_true",
                        help=port_range_help)

    args = parser.parse_args()

    if len(args.ports) < 2 or not args.port_range:
        ports = args.ports
    else:
        # User wants a range of ports. Need to create a list of ints
        # using range then convert to list of str.
        ports = range(int(args.ports[0]), int(args.ports[len(
            args.ports)-1])+1)
        # The next line of code won't work in Python 3. This should
        # not be an issue however as I don't believe that the Nmap
        # library has been ported to Python 3.
        ports = map(str, ports)

    # Let's scan!
    tcp_scan = TCPNULLScan(args.host_ip4, ports)
    tcp_scan.start_scan()
