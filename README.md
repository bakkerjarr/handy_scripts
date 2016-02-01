# Handy Scripts
This repository contains a collection of scripts for completing various tasks. There is no guarantee that the scripts will be maintained after being committed.

##Dependencies
The lists below contain software packages, libraries and modules necessary for each script to work.

###Network Scans and Pings

####Nmap Scans
The below script utilises the Nmap Python library to a TCP SYN scan. Nmap is used as it can provide informative output and has support for IPv6 as well.

#####nmap_tcp_syn_scan.py
- Python 2
- python-nmap

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