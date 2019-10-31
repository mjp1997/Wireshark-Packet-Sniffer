import socket
import struct 


def retrieveSocket():
    #params = 1. - Family of socket (ours is iPv6) 2. - Type of socket, 3. - Must select IP-based protocols
    my_socket = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
    return my_socket 

def main():
    retrieveSocket()

if __name__ == "__main__":
    main()
