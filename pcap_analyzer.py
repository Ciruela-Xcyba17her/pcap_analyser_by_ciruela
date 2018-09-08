"""
For information of .pcap , look https://wiki.wireshark.org/Development/LibpcapFileFormat
"""

import math
import struct
import sys
import os
import re
from tool_func import equal_count, equal_index, print_irregal_param_found
from packet_define import *
from print_func import *

def readpcap(filename):
    f = open(filename, 'rb')
    packets = []
    packets_index = 0

    pcap_header = Pcap_header(f.read(24))

    while True:
        pcap_packet_header_plain = f.read(16)
        if pcap_packet_header_plain == b'':
            break
        pcap_packet_header = Pcap_packet_header(pcap_packet_header_plain)
        pcap_packet_data_plain = f.read(pcap_packet_header.incl_len)
        pcap_packet_data = Pcap_packet_data(pcap_packet_data_plain)

        packet = Pcap_packet(packets_index, pcap_packet_header, pcap_packet_data)
        packets_index += 1

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

    packets_len = len(packets)

    regex_addr = r"(^([0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-f]{0,4}:){7}[0-9a-f]{0,4}$|^([0-9a-f]{0,2}:){5}[0-9a-f]{0,2}$)"
    addr_pattern = re.compile(regex_addr)
    regex_hyphen_number = r"^[0-9]+-[0-9]+$"
    hyphen_number_pattern = re.compile(regex_hyphen_number)
    regex_number_only = r"^[0-9]+$"
    number_only_pattern = re.compile(regex_number_only)

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
            
            #if equal_count(cmd, "-h"):
            if equal_count(cmd, "-ir"):
                cmd_index = equal_index(cmd, "-ir")
                index_range_str = cmd[cmd_index + 1]
                hnpm = hyphen_number_pattern.match(index_range_str)
                
                if hnpm:
                    tmp_packets = []
                    start_index_str, end_index_str = index_range_str.split('-')
                    start_index = int(start_index_str) - 1
                    end_index = int(end_index_str) - 1

                    if start_index < 1:
                        start_index = 1
                    if end_index > packets_len:
                        end_index = packets_len

                    for i in range(len(copied_packets)):
                        if start_index <= copied_packets[i].index <= end_index:
                            tmp_packets.append(copied_packets[i])
                    copied_packets = tmp_packets

                nop = number_only_pattern.match(index_range_str)
                if nop:
                    tmp_packets = []
                    tmp_packets.append(copied_packets[int(index_range_str) - 1])
                    copied_packets = tmp_packets

            if equal_count(cmd, "-s"):
                cmd_index = equal_index(cmd, "-s")
                src = cmd[cmd_index + 1]
                m = addr_pattern.match(src)
                if m:
                    tmp_packets = []
                    for i in range(len(copied_packets)):
                        if copied_packets[i].pcap_data.eth_frame.ip_packet.src_addr == src:
                            tmp_packets.append(copied_packets[i])
                    copied_packets = tmp_packets
                else:
                    print_irregal_param_found(cmd, cmd_index)
                    continue

            if equal_count(cmd, "-d"):
                cmd_index = equal_index(cmd, "-d")
                dst = cmd[cmd_index + 1]
                m = addr_pattern.match(dst)
                if m:
                    tmp_packets = []
                    for i in range(len(copied_packets)):
                        if copied_packets[i].pcap_data.eth_frame.ip_packet.dst_addr == dst:
                            tmp_packets.append(copied_packets[i])
                    copied_packets = tmp_packets
                else:
                    print_irregal_param_found(cmd, cmd_index)
                    continue
                
            

            print_packet_roughly(copied_packets)
            continue 

        if cmd[0] == "info":
            
            if cmd[1].isdecimal():
                packet_index = int(cmd[1]) - 1
                
                if 1 <= packet_index <= packets_len:
                    packet_index = int(cmd[1]) - 1
                    packets[packet_index].pcap_data.eth_frame.info()
                    packets[packet_index].pcap_data.eth_frame.ip_packet.info()
                    print('-'* 27 + " Packet data " + '-'* 27)
                    print_data(packets[packet_index].pcap_data.eth_frame.ip_packet.ip_data)
                else:
                    print("info: Index out of range. --- %d" % (packet_index+1))
            else:
                print("info: Illegal parameter %s" % str(cmd[1]))
        continue
        
        print("%s: Command not found." % cmd[0])

if __name__=="__main__":
    #a = b'\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f'
    #print_data(a)
    main()
    
