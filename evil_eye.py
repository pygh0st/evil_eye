#  known malware-serving domains from a master list generated at:
#  http://mirror2.malwaredomains.com/files/justdomains
import socket
import os
import struct
import sys
import urllib.request
import dns.reversename
from time import localtime
from time import strftime
from colorama import Fore
from scapy.all import MTU

# globals
log_buffer = list()
ETH_P_ALL = 3

# sniff incoming and outgoing traffic
class Nose:
    # initialize our class upon instantiation
    def __init__(self, iface, on_inbound, on_outbound):
        self.iface = iface
        self.on_inbound = on_inbound
        self.on_outbound = on_outbound

        # the raw in socket is a L2 raw socket that listens for all
        # packets going through the specified interface
        self.insock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.insock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        self.insock.bind((self.iface, ETH_P_ALL))

    # ip frame processor
    def __process_ipframe(self, pk_type, ip_head, payload):
        # unpack the ip header
        fields = struct.unpack('!BBHHHBBHII', ip_head)
        # tmp_hdrlen = fields[0] & 0xF
        ip_len = fields[2]

        # extract useful data
        ip_src = payload[12:16]
        ip_dest = payload[16:20]
        ip_frame = payload[0:ip_len]

        # pass values to inbound/outbound methods
        if pk_type == socket.PACKET_OUTGOING:
            if self.on_outbound is not None:
                self.on_outbound(ip_src, ip_dest, ip_frame)
        else:
            if self.on_inbound is not None:
                self.on_inbound(ip_src, ip_dest, ip_frame)

    # the receiver loop
    def recv(self):
        try:
            while True:
                packet, sa_11 = self.insock.recvfrom(MTU)

                if type == socket.PACKET_OUTGOING and self.on_outbound is None:
                    continue
                elif self.on_outbound is None:
                    continue

                if len(packet) <= 0:
                    break

                # grab the ethernet header
                eth_head = struct.unpack('!6s6sH', packet[0:14])
                # dummy_eth_protocol = socket.ntohs(eth_head[2])

                if eth_head[2] != 0x800:
                    continue

                # extract the ip header from the raw packet
                ip_head = packet[14:34]
                payload = packet[14:]

                self.__process_ipframe(sa_11[2], ip_head, payload)
        except KeyboardInterrupt:
            pass

# inbound listener
def inbound_callbacks(src, dest, frame):
    print('inbound: | src=%s | dest=%s | frame length=%d' % (socket.inet_ntoa(src), socket.inet_ntoa(dest), len(frame)))
    eyes(socket.inet_ntoa(src), 'inbound')

#outbound listener
def outbound_callbacks(src, dest, frame):
    print('outbound: | src=%s | dest=%s | frame length=%d' % (socket.inet_ntoa(src), socket.inet_ntoa(dest), len(frame)))
    eyes(socket.inet_ntoa(dest), 'outbound')

# the download function
def list_dl():
    list_url = 'http://mirror2.malwaredomains.com/files/justdomains'

    with urllib.request.urlopen(list_url) as response, open('evil_domains', 'wb') as out_file:
        data = response.read()
        out_file.write(data)
    out_file.close()

# look for evil domains in inbound/outbound traffic
def eyes(ip_addr, in_or_out):
    domain = dns.reversename.from_address(ip_addr)
    with open('evil_domains', 'r') as master:
        d_list = list(master)
        if domain in d_list:
            alert(str(domain), in_or_out)
            master.close()
        else:
            master.close()

# write alerts to the log_buffer
def logger(alert_str):
    global log_buffer
    log_buffer.append(alert_str)

# throw up an alert and log when a match is found
def alert(domain, in_or_out):
    alert_time = strftime("%d %b %Y %H:%M:%S", localtime())
    alert_str = str(alert_time + ' [' + in_or_out + '] ' + ' connection to ' + domain + ' was detected\n')
    print(Fore.RED + alert_str)
    logger(alert_str)

# write the log_buffer to file when program exits main loop
def scribe():
    global log_buffer
    with open('alert_log', 'a') as log:
        # iterate through the length of the list and write each value to file
        for x in range((len(log_buffer) - 1)):
            log.write(str(log_buffer[x]))
    log.close()

# usage guide
def usage():
    print('evil_eye.py traffic analyzer dirty beta by pygh0st')
    print()
    print('\tUsage: evil_eye.py [interface_name]')
    print('\nIf no interface is provided as an argument, a list of available devices in /sys/class/net/ will be provided\n\n')
    sys.exit(0)

def brain():
    global log_buffer

    # download the malware domain list
    #list_dl()

    # get list of available network interfaces
    interfaces = os.listdir('/sys/class/net/')

    # make sure the interface parameter was passed
    if not len(sys.argv[1:]):
        usage()

    # check that a valid interface was passes
    if sys.argv[1] in interfaces:
        sniffer = Nose(sys.argv[1], inbound_callbacks, outbound_callbacks)
        sniffer.recv()
    else:
        print("Invalid interface provided. Available interfaces are:")
        for x in range((len(interfaces) - 1)):
            print(interfaces[x])
        usage()

# start the brain
brain()