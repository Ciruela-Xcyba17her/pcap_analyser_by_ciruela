"""
For information of .pcap , look https://wiki.wireshark.org/Development/LibpcapFileFormat
"""

import struct
import sys
import tool_func
from packet_define import *

def readpcap(filename):
    f = open(filename, 'rb')
    packets = []

    pcap_header = Pcap_header(f.read(24))
    pcap_header.info()

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

    packets[12].pcap_header.info()
    packets[12].pcap_data.eth_frame.info()
    packets[12].pcap_data.eth_frame.ip_packet.info()

if __name__=="__main__":
    main()
