"""
For information of .pcap , look https://wiki.wireshark.org/Development/LibpcapFileFormat
"""

import math
import struct
import sys
import os
import re
import tool_func
from packet_define import *
from print_func import *

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
    
    pcap_base_ts_sec = packets[0].pcap_header.ts_sec 
    pcap_base_ts_usec = packets[0].pcap_header.ts_usec
    for i in range(len(packets)):
        if packets[i].pcap_header.ts_usec >= pcap_base_ts_usec:
            packets[i].pcap_header.ts_sec -= pcap_base_ts_sec
            packets[i].pcap_header.ts_usec -= pcap_base_ts_usec
        else:
            kurisage = 10 ** int(math.log10(pcap_base_ts_usec) + 1)
            packets[i].pcap_header.ts_sec -= (pcap_base_ts_sec + 1)
            packets[i].pcap_header.ts_usec = packets[i].pcap_header.ts_usec + kurisage - pcap_base_ts_usec

    return packets

def main():
    args = sys.argv
    if len(sys.argv) != 2:
        print("Usage: pcap_analyzer.py [pcap_filepath]")
        sys.exit(1)

    FILENAME = args[1]

    print_logo()
    if not os.path.exists(sys.argv[1]):
        print("[ ! ] \"%s\" not found. " % sys.argv[1])
        sys.exit(1)

    print("[ + ] Reading input pcap file...")
    packets = readpcap(FILENAME)
    print("[ + ] Reading finished!\n")

    while True:
        cmd = input("command> ").split()
        cmd_len = len(cmd)
        if cmd_len == 0:
            continue
        
        if cmd[0] == "exit":
            sys.stdout.write("\n")
            sys.exit(0)
        
        copied_packets = packets

        if cmd[0] == "show":
            if cmd_len == 1:
                print_packet_roughly(copied_packets)
                continue

            if cmd.count("-src"):
                cmd_index = cmd.index("-src")
                src = cmd[cmd_index + 1]
                m = re.match(r"(([0-9]{1,3}\.){3}[0-9]{1,3}|([0-9a-f]{0,4}:){7}[0-9a-f]{0,4}|([0-9a-f]{0,2}:){5}[0-9a-f]{0,2})", src)
                if m:
                    tmp_packets = []
                    for i in range(len(copied_packets)):
                        if copied_packets[i].pcap_data.eth_frame.ip_packet.src_addr == src:
                            tmp_packets.append(copied_packets[i])
                    copied_packets = tmp_packets
                else:
                    print("find: -src: Irregal argument \"%s\". " % cmd[cmd_index + 1])
                    continue

            if cmd.count("-dst"):
                cmd_index = cmd.index("-dst")
                dst = cmd[cmd_index + 1]
                m = re.match(r"(([0-9]{1,3}\.){3}[0-9]{1,3}|([0-9a-f]{0,4}:){7}[0-9a-f]{0,4}|([0-9a-f]{0,2}:){5}[0-9a-f]{0,2})", src)
                if m:
                    tmp_packets = []
                    for i in range(len(copied_packets)):
                        if copied_packets[i].pcap_data.eth_frame.ip_packet.dst_addr == dst:
                            tmp_packets.append(copied_packets[i])
                    copied_packets = tmp_packets
                else:
                    print("find: -dst: Irregal argument \"%s\". " % cmd[cmd_index + 1])
                    continue



            print_packet_roughly(copied_packets)
            continue 

        
        
        print("%s: Command not found." % cmd[0])

if __name__=="__main__":
    main()
