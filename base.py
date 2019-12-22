from datetime import datetime
import struct
import os
import socket as s
from datetime import datetime
​
# Used to get he IP address of the host machine which is used
# to determine what IP ranges to ping.
def find_local_ip():
    ip = s.gethostbyname(s.gethostname())
    if ip[-2] == '.':
        ip = ip[:-1]
    if ip[-3] == '.':
        ip = ip[:-2]
    if ip[-4] == '.':
        ip = ip[:-3]
    print(ip)
    return ip
​
# Function is used to sniff current traffic on the network
def sniff_packets():
    proto_filter = input("Please inter a protocol number to filter (type 'all' for no filter)\n\t===:")
    if proto_filter != 'all':
        try:
            proto_filter = int(proto_filter)
        except:
            print("-ERROR----------")
​
            # This input allows the screen to pause for the user to view the data
            request = input("Please try again with valid input\nEnter any key to continue")
            return
    ip_filter = input("Please type in a filter for ip address (type 'all' for no filter)\n\t===:")
# A raw socket is created and its properties are set to allow
# it to capture all packets.
    soc = s.socket(s.AF_INET, s.SOCK_RAW, s.IPPROTO_IP)
    soc.bind(("localhost", 0))
    soc.setsockopt(s.IPPROTO_IP, s.IP_HDRINCL, 1)
    soc.ioctl(s.SIO_RCVALL, s.RCVALL_ON)
    s.setdefaulttimeout(10)
    packet_list = []
​
# This try block is to capture when the user interrupts the loop with the keyboard
    try:
        while True:
​
# This try block is incase we dont recieve a packet in the timeout duration
            try:
​
# A captured packet is proessed by sending it into the ip_header function
                data = soc.recvfrom(60000)
                packet = data[0]
                parsed_packet = ip_header(packet)
​
# If the current display has 20 items the control will return to hte main screen
                if len(packet_list) >= 20:
                    return
                else:
                    packet_list.insert(len(packet_list),parsed_packet)
    # The print packet function is called to display and refresh the packet list
                print_packet_list(packet_list,proto_filter,ip_filter)
            except:
                pass
# Keyboard pressed during while loop
    except KeyboardInterrupt:
        return
# Function used to display the packets
def print_packet_list(packet_list,proto_filter,ip_filter):
    print("Current Filters\tIp Filter:"+ip_filter+" Protocol Filter:"+proto_filter)
​
    print("\n\t List of 20 most current Packets as of "+datetime.now().strftime("%H:%M:%S"))
    print("Source IP \t\t Destination IP \t Protocol \tSource Port \tDestination Port \t\tTimestamp")
    for x in packet_list:
        if ip_filter != 'all':
            if x.data["Source Address"] != ip_filter:
                continue
        if proto_filter != 'all':
            if x.data["Protocol"] != proto_filter:
                continue
        print(x.data["Source Address"], end="\t")
        print(x.data["Destination Address"], end="\t\t")
        print(x.data["Protocol"], end="\t\t\t")
        print(x.data["Source Port"], end="\t\t\t")
        print(x.data["Destination Port"], end="\t\t\t\t\t\t")
        print(x.data["Timestamp"])
​
# This function is used to parse the given packet by creating a captured_packet class object
def ip_header(packet):
    current_packet = captured_packet()
​
# Different parts of the header are given to the class to contrust the data
    current_packet.general_information(packet[0:20],packet[34:54],packet[14:34])
    return current_packet
​
# This function is takes in an IP and a port and performs a scan to see
# If the port is open
def port_scan(target,port):
    try:
        soc = s.socket(s.AF_INET, s.SOCK_STREAM)
        con = soc.connect((target, port))
        return True
    except:
        return False
​
# This function takes in an ip address and calls the sub function
# that will check the port
def run_port_scan(ip):
    res = {}
    for x in range(2, 200):
        if port_scan(ip, x):
            res[x] = "Open"
    print("Results")
    print("------------------")
    for x in res:
        print(x)
​
# This input allows the screen to pause for the user to view the data
    request = input("Enter any key to continue")
    return
​
# This ping sweep pings the given ip to see if its active
def ping_sweeper(ip):
# The os.system runs the given cmd on the cmd line
    status = os.system("ping "+ip+" -c 1")
    if status == 0:
        return True
    else:
        pass
​
# Given a starting ip address xxx.xxx.xxx.??? this function will
# Generate the full ip address for the range that needs to be tested
# and then it will call the subfunction
def run_ping_sweeper(ip):
    res = {}
    for x in range(1, 15):
        iptest = ip+str(x)
        if ping_sweeper(iptest):
            res[iptest] = "Active"
    print("\n\n\n\n\n\n\n\n\n\n")
    print("Results")
    print("------------------")
    for x in res:
        print(x + " : Active")
# This input allows the screen to pause for the user to view the data
    request = input("Enter any key to continue")
    return
​
# This function prints the main screen
def print_main_screen():
    print("Welcome to the WIFI Piranha")
    print("Programmers - Mitch Perez - Joseph Proctor - Paul Durham")
    print("\n\n||==========================||")
    print("Please note the following"
          "\n\tThis file must be ran with admin access for it to function"
          "\n\tYour NIC device must be in promiscuous mode"
          "\n\tYou must have your fire wall turned off.")
    print("||==========================||")
    print("Select from one of the following options")
    print("(1) View packets on the network")
    print("(2) Locate all active devices on the network")
    print("(3) Scan for open ports")
    print("(4) Exit program")
    request = input("\t===:")
    if request == '1':
        sniff_packets()
        return
    elif request == '2':
        run_ping_sweeper(find_local_ip())
        print("working on it...")
        return
    elif request == '3':
        print("Please enter an IP address")
        ip = input('====:')
        print("working on it...")
        run_port_scan(ip)
        return
    elif request == '4':
        exit(0)
    else:
        print("Please enter a valid request")
        request = input("Enter any key to continue")
        return
​
​
def load_properties(file):
    res = {}
    with open(file) as properties_file:
        for lines in properties_file:
            temp = lines.split('=')
            res[int(temp[0].strip())] = [temp[1].strip()]
    return res
​
# Beginning of the captured_packet class
class captured_packet:
    PROPERTIES_PROTO = load_properties('protocol_identifiers.properties')
    PROPERTIES_PORTS = load_properties('port_info.properties')
​
    def __init__(self):
        self.data = {}
​
# Raw binary is fed into ths function and its unpacked with the struct package
    def general_information(self, packet_data, packet_from_data, ip_data):
        iph = struct.unpack('!BBHHHBBH4s4s', packet_data)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = (iph[6])
        s_addr = struct.unpack('BBBB', iph[8])
        d_addr = struct.unpack('BBBB', iph[9])
        self.data['Version'] = version
        self.data['IP Header Length'] = ihl
        self.data['Protocol'] = captured_packet.PROPERTIES_PROTO[protocol][0]
        source = ""
        for x in s_addr:
            source += str(x) + "."
        self.data['Source Address'] = source[:-1]
        des = ""
        for x in d_addr:
            des += str(x) + "."
        self.data['Destination Address'] = str(des[:-1])
        self.data['Timestamp'] = datetime.now().strftime("%H:%M:%S")
        storeobj = struct.unpack('!HHLLBBHHH', packet_data)
        source_port = storeobj[0]
        destination_port = storeobj[1]
        sequence_number = storeobj[2]
        acknowledge_number = storeobj[3]
        offset_reserved = storeobj[4]
        tcp_flag = storeobj[5]
        window = storeobj[6]
        checksum = storeobj[7]
        urgent_pointer = storeobj[8]
        self.data["Source Port"] = source_port
        self.data["Destination Port"] = destination_port
        self.data["Sequence Number"] = sequence_number
        self.data["Acknowledge Number"] = acknowledge_number
        self.data["Offset & Reserved"] = offset_reserved
        self.data["Tcp Flag"] = tcp_flag
        self.data["Window"] = window
        self.data["CheckSum"] = checksum
        self.data["Urgent Pointer"] = urgent_pointer
        storeobj = struct.unpack("!BBHHHBBH4s4s", ip_data)
        version = storeobj[0]
        tos = storeobj[1]
        total_length = storeobj[2]
        identification = storeobj[3]
        fragment_Offset = storeobj[4]
        ttl = storeobj[5]
        header_checksum = storeobj[7]
        destination_address = s.inet_ntoa(storeobj[8])
        self.data["Protocol"] = protocol
        self.data["Header CheckSum"] = header_checksum
        self.data["Destination Address"] = destination_address
​
​
def main():
    while True:
        print_main_screen()
​
​
main()