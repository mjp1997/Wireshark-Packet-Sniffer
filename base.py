#!/usr/bin/python
import struct
import socket
import textwrap
import binascii

def retrieve_eth_frame(my_info):
    #unpacking ethernet packets, converting from binary 
    destination_mac, source_mac, prototype = struct.unpack('! 6s 6s H', my_info[0:14])
    #converts mac address soruce, destination and type into readable formats
    destination_mac, source_mac = format_mac(destination_mac), format_mac(source_mac)
    #return formatted mac addresses, ensuring indanness is correct
    return destination_mac, source_mac, socket.htons(prototype), my_info

def format_mac(formatted_address):
    #format address here
    return formatted_address

    