import struct
import sys
from data_dictionary_define import *
from tool_func import *


class Pcap_header():
    def __init__(self, pcap_header_plain):
        ph = my_struct_unpack_hex('little', [4, 2, 2, 4, 4, 4, 4], pcap_header_plain)

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
        print("data link type : %s" % LINK_TYPES[self.network])
        print("\n")


class Pcap_packet_header():
    def __init__(self, pcap_packet_header_plain):
        ph = my_struct_unpack_hex('little', [4, 4, 4, 4], pcap_packet_header_plain)

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
        print('-' * 20 + " pcap_packet data info " + '-' * 20)
        print(self.eth_frame)
        sys.stdout.write("\n")


class Pcap_packet():
    def __init__(self,index, header, data):
        self.index = index
        self.pcap_header = header
        self.pcap_data = data


class Ethernet_ii_frame():
    def __init__(self, ethernet_ii_plain):
        self.dst_mac, self.src_mac = "", ""
        for i in range(6):
            self.dst_mac += (("%02x" % ethernet_ii_plain[i]) + ':')
            self.src_mac += (("%02x" % ethernet_ii_plain[6 + i]) + ':')
        self.dst_mac = self.dst_mac[:-1]
        self.src_mac = self.src_mac[:-1]
        
        self.eth_type_code = struct.unpack_from(">H", ethernet_ii_plain, 12)[0]
        self.eth_type_name = ETH_TYPES[self.eth_type_code]
        
        #print(DEFINED_ETHTYPES)
        if DEFINED_ETHTYPES.count(self.eth_type_name) == 0:
            self.ip_packet = Undefined_packet(ethernet_ii_plain[14:])
        elif self.eth_type_name == "IPv4":
            self.ip_packet = Ipv4_packet(ethernet_ii_plain[14:])
        elif self.eth_type_name == "IPv6":
            self.ip_packet = Ipv6_packet(ethernet_ii_plain[14:])

        #self.fcs = ethernet_ii_plain[-4:]

    def info(self):
        print('-' * 20 + " Ethernet II frame info " + '-' * 20)
        print("Source MAC Address : %s" % self.src_mac)
        print("Destination MAC Address : %s" % self.dst_mac)
        print("EtherType : %s\n" % self.eth_type_name)

class Undefined_packet():
    def __init__(self, plain_data):
            self.src_addr = ""
            self.dst_addr = ""
            self.length = ""
            self.protocol_name = ""
            self.ip_data = plain_data

    def info(self):
        print('-' * 20 + " ** EtherType Undefined ** " + '-' * 20)

###############################################################
# Layer 3
###############################################################

class Ipv4_packet():

    def __init__(self, plain_data):
        size_list = [4, 4, 8, 16, 16, 3, 13, 8, 8, 16, 32, 32]
        d = my_struct_unpack_bin("big", size_list, plain_data)
        self.ip_version = d[0]
        self.ihl = 4 * d[1]
        self.tos = d[2] # class to describe IP-precedence, etc, will be added.
        self.length = d[3]
        self.identification = d[4]
        self.flags = d[5]
        self.fragment_offset = d[6]
        self.ttl = d[7]
        self.protocol_code = d[8]
        self.protocol_name = IPv4_PROTOCOLS[d[8]]
        self.checksum = d[9]

        self.src_addr, self.dst_addr = "", ""
        src_addr_plain = d[10]
        dst_addr_plain = d[11]
        for i in range(4):
            src_addr_content = (src_addr_plain >> (3 - i)*8) & 0xFF
            dst_addr_content = (dst_addr_plain >> (3 - i)*8) & 0xFF
            self.src_addr += ("%d." % src_addr_content)
            self.dst_addr += ("%d." % dst_addr_content)
        self.src_addr = self.src_addr[:-1]
        self.dst_addr = self.dst_addr[:-1]
        self.option = plain_data[20:self.ihl]
        self.ip_data = plain_data[self.ihl:]

    def info(self):
        print('-' * 20 + " IPv4 Packet info " + '-' * 20)
        print("IP_version : %d" % self.ip_version)
        print("IHL(bytes) : %d" % self.ihl)
        print("Type_of_Service : %d (more descriptions will be added...)" % self.tos)
        print("Total length (bytes) : %d" % self.length)
        print("Identification : 0x%x" % self.identification)
        print("Flags : [Reserved:%d, Fragment_allowed:%d, Is_final_fragment:%d]" % (self.flags & 0b100 >> 2, self.flags & 0b010 >> 1, self.flags & 0b001))
        print("Fragment_Offset : %d" % self.fragment_offset)
        print("TTL : %d" % self.ttl)
        print("Protocol : %s" % self.protocol_name)
        print("Checksum : 0x%x" % self.checksum)
        print("Source_IP : %s" % self.src_addr)
        print("Destination_IP : %s\n" % self.dst_addr)
        #print("Option : %x" % self.option)
    
class Ipv6_packet():
    class Traffic_class():
        def __init__(self, data:int):
            self.DSCP = data & 0b11111100 >> 2
            self.ECT = data & 0b00000010 >> 1
            self.CE = data & 0b00000001

    def __init__(self, plain_data):
        read_size_list = [4, 8, 20, 16, 8, 8, 128, 128]
        d = my_struct_unpack_bin('big', read_size_list, plain_data)
        self.version = d[0]
        self.traffic_class = self.Traffic_class(d[1])
        self.flow_label = d[2]
        self.length = d[3]
        self.next_header = d[4]
        self.hop_limit = d[5]
        self.src_addr = read_ipv6_addr(d[6])
        self.dst_addr = read_ipv6_addr(d[7])

    def info(self):
        print('-' * 20 + " IPv6 Packet info " + '-' * 20)
        print("version : %d" % self.version)
        print("traffic class -\n\tDSCP:%d\n\tECT:%d\n\tCE:%d" % (self.traffic_class.DSCP, self.traffic_class.ECT, self.traffic_class.CE))
        print("flowlabel : %05x" % self.flow_label)
        print("")

##########################################################
# Layer 4
##########################################################

class TCP_segment():
    class Flags():
        def __init__(self, data:int):
            self.CWR = data & 0x80 >> 7
            self.ECE = data & 0x40 >> 6
            self.URG = data & 0x20 >> 5
            self.ACK = data & 0x10 >> 4
            self.PSH = data & 0x08 >> 3
            self.RST = data & 0x04 >> 2
            self.SYN = data & 0x02 >> 1
            self.FIN = data & 0x01

    def __init__(self, plain_data):
        read_size_list = [16, 16, 32, 32, 4, 4, 8, 16, 16, 16, 24, 8]
        d = my_struct_unpack_bin('big', read_size_list, plain_data)
        self.src_port_num = d[0]
        self.src_port_name = TCP_PORTS[d[0]]
        self.dst_port_num = d[1]
        self.dst_port_name = TCP_PORTS[d[1]]
        self.seq_num = d[2]
        self.ack_num = d[3]
        self.data_offset = d[4]
        self.reserved = d[5]
        self.flags = self.Flags(d[6])
        self.window_size = d[7]
        self.checksum = d[8]
        self.urgent_pointer = d[9]
        self.options = d[10]
        self.padding = d[11]
        self.tcp_data = plain_data[sum(read_size_list)]

class UDP_segment():
    def __init__(self, plain_data):
        d = read_size_list = [16, 16, 16, 16]
        self.src_port_num = d[0]
        self.src_port_name = TCP_PORTS[d[0]]
        self.dst_port_num = d[1]
        self.dst_port_name = TCP_PORTS[d[1]]
        self.length = d[2]
        self.checksum = d[3]
        self.tcp_data = plain_data[sum(read_size_list):]

    

