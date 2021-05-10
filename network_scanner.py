#!/usr/bin/env python

import scapy.all as scapy
"""
scapy is a libary that provides tools making it possible to interact with network packets, this allows me to 
create this program that allows me to scan the network and create a list of devices on it.
"""

"""
Network scanner allows for the user too scan and identify all of the devices on a network. This program I have created
is designed to identify all of the devices/hosts on a local ethernet network.
"""

def scan(ip):
    answered_list = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), timeout=1, verbose=False)
    # here the program uses srp to send ARP pings to discover hosts on the local network, and return the ip
    # and mac address of the targets, it is then returned and stored in answered_list

    return answered_list
    # The program then returns the list to the MainWindow
