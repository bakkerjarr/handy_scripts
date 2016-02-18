#!/usr/bin/env python

from prettytable import PrettyTable
from sys import exit
import argparse
import signal

import nmap

__author__ = "Jarrod N. Bakker"
__status__ = "Untested."


class TCPXMASScan:
    """Use Nmap to port scan a host. A TCP XMAS scan is used.
    """

    _NMAP_FLAGS = "-sX"
    _RESULT_FILENAME = "scan_results.log"

    def __init__(self, host, ports):
        """Initial fields and handlers.

        :param host: IPv4 address of target host.
        :param ports: Port numbers to scan.
        """
        self._host = host
        self._ports = ports
        self._file = None
        # Register a handler for catching Ctrl+c
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, signal, frame):
        """Catch Ctrl+C and terminate the script somewhat gracefully.
        """
        string = "[!] Terminating script."
        print(string)
        if self._file is not None:
            self._file.write(string + "\n")
            self._file.close()
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
        """Start the TCP XMAS scan.
        """
        results = {}
        self._file = open(self._RESULT_FILENAME, "a")
        string = ("[?] Starting TCP XMAS scan on host {0}".format(
            self._host))
        print(string)
        self._file.write(string + "\n")
        for port in self._ports:
            scan_result = self.scan_port(self._host, port)
            string = ("[*] {0} tcp/{1} {2}".format(self._host, port,
                                                   scan_result))
            print(string)
            self._file.write(string + "\n")
            if scan_result not in results:
                results[scan_result] = [port]
            else:
                results[scan_result].append(port)
        string = "[+] Scan complete."
        print(string)
        self._file.write(string + "\n")
        string = ("[?] Printing results of the port scan. Please see\n"
                  "https://nmap.org/book/man-port-scanning-basics.html\n"
                  "for a description of the six port states recognised "
                  "by Nmap.")
        print string
        self._file.write(string + "\n")
        string = (self._format_results(results))
        print string
        self._file.write(string + "\n")
        self._file.close()

    def _format_port_line(self, values):
        """Format a list of port numbers into a string with new lines.

        :param values: List of port number values.
        :return: Formatted string.
        """
        separator = ", "
        line_len = 0
        value_str = ""
        values_len = len(values)
        count = 0
        for value in values:
            if line_len > 52:
                value_str += "\n"
                line_len = 0
            if count+1 != values_len:
                value_str += str(value) + separator
            else:
                value_str += str(value)
            line_len += len(str(value)) + len(separator)
            count += 1
        return value_str

    def _format_results(self, results):
        """Format the results of the Nmap port scan to the terminal
        window.

        :param results: Dict of results.
        :return: Formatted results of the scan as a string.
        """
        table = PrettyTable(["Port Status", "Port Number/s"])
        table.align["Port Status"] = "l"
        table.align["Port Number/s"] = "r"
        for port_status in results:
            value_str = self._format_port_line(results[port_status])
            table.add_row([port_status, value_str])
        return table.get_string()

if __name__ == "__main__":
    # TODO Add command line argument checking.
    # Process CLI arguments
    program_desc = "Use Nmap to perform a TCP XMAS Scan on a host."
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
    tcp_scan = TCPXMASScan(args.host_ip4, ports)
    tcp_scan.start_scan()
