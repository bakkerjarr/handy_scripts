# Handy Scripts
This repository contains a collection of scripts for completing various tasks. There is no guarantee that the scripts will be maintained after being committed.

##Dependencies
The lists below contain software packages, libraries and modules necessary for each script to work.

###Network Scans and Pings

####Nmap Scripts
These scripts use the Nmap module for Python to perform various network scans. Nmap is used as it can provide informative output and works reliably with IPv6.
#####nmap_tcp_fin_scan.py
- Python 2
- python-nmap
- prettytable

#####nmap_tcp_null_scan.py
- Python 2
- python-nmap
- prettytable

#####nmap_tcp_syn_scan.py
- Python 2
- python-nmap
- prettytable

#####nmap_tcp_win_scan.py
- Python 2
- python-nmap
- prettytable

#####nmap_tcp_xmas_scan.py
- Python 2
- python-nmap
- prettytable

#####nmap_udp_scan.py
- Python 2
- python-nmap
- prettytable

####Scapy Scripts
These scripts use the Python module Scapy to perform some basic network scans. Note that the scripts must be executed with root privileges in order for them to work.
#####scapy_ping.py
- Python 2
- Scapy

#####scapy_tcp-ping.py
- Python 2
- Scapy

#####scapy_udp-ping.py
- Python 2
- Scapy