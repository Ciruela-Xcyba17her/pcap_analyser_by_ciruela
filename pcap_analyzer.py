"""
For information of .pcap , look https://wiki.wireshark.org/Development/LibpcapFileFormat
"""

import struct
import sys
import tool_func
import data_dictionary_define as dic

class Pcap_header():
    def __init__(self, pcap_header_plain):
        ph = struct.unpack("<IHHIIII", pcap_header_plain)

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
        print("data link type : %s" % dic.LINK_TYPES[self.network])
        print("\n")

class Pcap_packet_header():
    def __init__(self, pcap_packet_header_plain):
        ph = struct.unpack("<IIII", pcap_packet_header_plain)

        self.ts_sec = ph[0]
        self.ts_usec = ph[1]
        self.incl_len = ph[2]
        self.orig_len = ph[3]
    
    def info(self):

        print('-' * 20 + " pcap_packet header info " + '-' * 20)
        print("timestamp : %d.%d" % (self.ts_sec, self.ts_usec) )
        print("pcap_packet length (in this file) : %d" % self.incl_len)
        print("pcap_packet length (original capture) : %d" % self.orig_len)
        sys.stdout.write("\n")
        

class Pcap_packet_data():
    def __init__(self, pcap_packet_data_plain):
        self.eth_frame = Ethernet_ii_frame(pcap_packet_data_plain)
    
    def info(self):
        print('-' * 20 + " packet data info " + '-' * 20)
        print(self.eth_frame)
        sys.stdout.write("\n")

class Pcap_packet():
    def __init__(self, header, data):
        self.pcap_header = header
        self.pcap_data = data

class Ethernet_ii_frame():
    def __init__(self, ethernet_ii_plain):
        self.dst_mac, self.src_mac = [], []
        for i in range(6):
            self.dst_mac.append(ethernet_ii_plain[i])
        for i in range(6):
            self.src_mac.append(ethernet_ii_plain[6 + i])
        self.eth_type_code = struct.unpack_from(">H", ethernet_ii_plain, 12)[0]
        self.eth_type_name = dic.ETH_TYPES[self.eth_type_code]
        self.fcs = ethernet_ii_plain[-4:]

    def info(self):
        print('-' * 20 + " ethernet II frame info " + '-' * 20)
        
        sys.stdout.write("source MAC Address : ")
        for i in range(6):
            sys.stdout.write("%02x" % self.src_mac[i])
            if i == 5:
                break
            sys.stdout.write(':')
        sys.stdout.write('\n')

        sys.stdout.write("destination MAC Address : ")
        for i in range(6):
            sys.stdout.write("%02x" % self.dst_mac[i])
            if i == 5:
                break
            sys.stdout.write(':')
        sys.stdout.write("\n")

        print("EtherType : %s\n" % self.eth_type_name)

def readpcap(filename):
    f = open(filename, 'rb')
    packets = []

    pcap_header = Pcap_header(f.read(24))

    while True:
        pcap_packet_header_plain = f.read(16)
        if pcap_packet_header_plain == b'':
            break
        pcap_packet_header = Pcap_packet_header(pcap_packet_header_plain)
        pcap_packet_data_plain = f.read(pcap_packet_header.incl_len)
        pcap_packet_data = Pcap_packet_data(pcap_packet_data_plain)

        packet = Pcap_packet(pcap_packet_header, pcap_packet_data)

        packets.append(packet)

    return packets

def main():
    args = sys.argv
    FILENAME = args[1]
    packets = readpcap(FILENAME)

    packets[0].pcap_header.info()
    packets[0].pcap_data.eth_frame.info()

    #for packet in packets:
    #    packet.data.info()


if __name__=="__main__":
    main()
