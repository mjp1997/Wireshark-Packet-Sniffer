#!/usr/bin/python
import struct
import socket
import textwrap
import binascii
import importlib
from retrieve_packets import *

#used to parse the header for necessary components
def retrieve_ethernet_header(my_info):
    #unpacking ethernet packets, converting from binary 
    eth_packet_header = my_info[0:14] 
    #retrieving ip header of processed information
    ip_header = my_info[14:34]
    #unpacking....
    destination_mac, source_mac, prototype = struct.unpack("!6s6s2s", eth_packet_header )
    #converts mac address soruce, destination and type into readable formats
    destination_mac, source_mac = format_mac(destination_mac), format_mac(source_mac)     
    return destination_mac, source_mac, socket.htons(prototype), my_info

def retrieve_mac_address():
    pass 

def format_mac(formatted_address):
    #format address here
    return formatted_address

if __name__ == "__main__":
    main()
