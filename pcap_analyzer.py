"""
For information of .pcap , look https://wiki.wireshark.org/Development/LibpcapFileFormat
"""

import struct
import sys
import tool_func
from data import link_types

class Pcap_header():
    def __init__(self, pcap_header_plain):
        ph = struct.unpack("<IHHIIII", pcap_header_plain)
        print(ph)

        self.magic = ph[0]
        self.version_major = ph[1]
        self.version_minor = ph[2]
        self.thiszone = ph[3]
        self.sigfigs = ph[4]
        self.snaplen = ph[5]
        self.network = ph[6]
    
    def info(self):
        print('-' * 10 + " pcap header info " + '-' * 10)
        print("pcap version : %d.%d" % (self.version_major, self.version_minor))
        print("timezone : %d" % self.thiszone)
        print("accuracy of timestamps : %d" % self.sigfigs)
        print("max length of captured packets (octets) : %d" % self.snaplen)
        print("data link type : %s" % link_types.LINK_TYPES[self.network])
        print("\n")

class Packet_header():
    def __init__(self, packet_header_plain):
        ph = struct.unpack("<IIII", packet_header_plain)

        self.ts_sec = ph[0]
        self.ts_usec = ph[1]
        self.incl_len = ph[2]
        self.orig_len = ph[3]
    
    def info(self):

        print('-' * 10 + " packet header info " + '-' * 10)
        print("timestamp : %d.%d" % (self.ts_sec, tool_func.int_to_float(self.ts_usec)) )
        print("packet length (in this file) : %d" % self.incl_len)
        print("packet length (original capture) : %d" % self.orig_len)
        print("\n")
        

class Packet_data():
    def __init__(self, packet_data_plain):
        self.data = packet_data_plain
    
    def info(self):
        print('-' * 10 + " packet data info " + '-' * 10)
        print(self.data)
        print("\n")

class Packet():
    def __init__(self, header, data):
        self.header = header
        self.data = data

"""
class Ethernet_ii_frame():
    def __init__(self, ethernet_ii_plain):
        self.dst_mac, self.src_mac = [], []
        for i in range(6):
            self.dst_mac.append(ethernet_ii_plain[i])
        for i in range(6):
            self.src_mac.append(ethernet_ii_plain[6 + i])
        self.frame_type 
"""     

def readpcap(filename):
    f = open(filename, 'rb')
    packets = []

    pcap_header = Pcap_header(f.read(24))
    pcap_header.info()

    while True:
        packet_header_plain = f.read(16)
        if packet_header_plain == b'':
            break
        packet_header = Packet_header(packet_header_plain)
        packet_data_plain = f.read(packet_header.incl_len)
        packet_data = Packet_data(packet_data_plain)

        packet = Packet(packet_header, packet_data)

        packets.append(packet)

    return packets

def main():
    args = sys.argv
    FILENAME = args[1]
    packets = readpcap(FILENAME)

    #for packet in packets:
    #    packet.data.info()


if __name__=="__main__":
    main()
