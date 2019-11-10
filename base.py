import struct
import sys
import os
import binascii
from _socket import *
​
import socket as s
​
​
def loadProperties():
    properties = {}
    with open('c:\\temp\\protocol_identifiers.properties') as properties_file:
        for lines in properties_file:
            temp = lines.split('=')
            properties[temp[0].strip()] = [temp[1].strip()]
def main():
    properties = loadProperties();
    s.socket = s.socket(AF_INET, SOCK_RAW, IPPROTO_IP)
    s.socket.bind(("localhost", 0))
    s.socket.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    s.socket.ioctl(SIO_RCVALL, RCVALL_ON)
    while True:
        data = s.socket.recvfrom(10000)
        packet = data[0]
        print(ip_header(packet))
​
​
def ip_header(packet):
    # take first 20 characters for the ip header
    header = packet[0:20]
​
    # now unpack them :)
    iph = struct.unpack('!BBHHHBBH4s4s', header)
​
    version_ihl = iph[0]
    version = version_ihl >> 4
    4
    ihl = version_ihl & 0xF
​
    iph_length = ihl * 4
​
    ttl = iph[5]
    protocol = iph[6]
    s_addr = struct.unpack('BBBB',iph[8])
    d_addr = struct.unpack('BBBB',iph[9])
​
    print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(
        protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
​
    tcp_header = packet[iph_length:iph_length + 20]
​
    # now unpack them :)
    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
​
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    4
​
    print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(
        sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
​
    h_size = iph_length + tcph_length * 4
    data_size = len(packet) - h_size
​
    # get data from the packet
    data = packet[h_size:]
​
    ## i need to parse this thing
   ## print('Data : ' + data)
​
​
​
main()