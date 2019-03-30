from typing import List
from packet_define import *

def int_to_float(d):
    print("d="+str(d))
    base = 1
    ret_d = 0

    for i in range(64):
        base /= 2
        if d << i & 0x8000 == 0x8000:
            ret_d += base
    
    return ret_d

def print_logo():
    print(" _____                          ___              _                   _ __      ")
    print("|  __ \\   __   ___  _ __       /   | _ __   ___ | | _  _  ____  ___ | /__|     ")
    print("| |__) | / _) / _ || /  \     / /| || /  | / _ || || || ||_  / / _ || /        ")
    print("|  ___/ | (_ | |/ ||  () |   / /_| || /| || |/ || || |/ / / /_| ___/| |        ")
    print("| |      \__)|__/_/| \__/   / ___  ||_||_||__/_/| | \_ / /____|\___/|_|        ")
    print("| |                | |     / /   | |            | | / /                        ")
    print("|_/                | |    /_/    | |            |_// /   by Ciruela            ")
    print("                   |_/           /_|              /_/      (@__Xcyba17her_)    ")
    print("                                                                               ")
    print("!!!!!!!!!!!!!!!!!! Under Construction Version !!!!!!!!!!!!!!!!!!!!!    ")
    print("URL: https://github.com/Ciruela-Xcyba17her/pcap_analyzer_by_ciruela    ")
    print("")

def print_data(bytes_data : List[bytes]):
    bytes_len = len(bytes_data)
    hex_data = []
    line_len = bytes_len // 16
    rest_offset = line_len * 16
    rest_num_of_data = bytes_len % 16

    for b in bytes_data:
        hex_data.append(b)

    for line_index in range(line_len):
        hex_line = ""
        ascii_line = ""

        for i in range(16):
            hex_line += ("%02x " % hex_data[line_index * 16 + i])
            if (i + 1) % 8 == 0:
                hex_line += ' '
        hex_line += ' '

        for i in range(16):
            h = hex_data[line_index * 16 + i]
            
            if 0x21 <= h <= 0x7e:
                c = chr(h)
            else:
                c = '.'
            
            ascii_line += c
        
        print(hex_line + ascii_line)

    hex_line = ""
    ascii_line = ""

    for i in range(rest_num_of_data):
        hex_line += ("%02x " % hex_data[rest_offset + i])
        if (i + 1) % 8 == 0:
            hex_line += ' '
    
    for i in range(rest_num_of_data):
        h = hex_data[line_len * 16 + i]
        if 0x21 <= h <= 0x7e:
            c = chr(h)
        else:
            c = '.'
        ascii_line += c
    
    print(hex_line.ljust(51) + ascii_line)

        
    
    
    

        
        

    

def print_packet_roughly(pcap_packets: List[Pcap_packet]):
    hyphen_num_list = [7, 9, 17, 17, 5, 15, 30]
    hyphen_list = []
    for i in range(len(hyphen_num_list)):
        hyphen_list.append('-' * hyphen_num_list[i])

    print("+".join(hyphen_list))
    #######1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890
    print("  No.  |   Time  |       src       |       dst       | len |   Protocol    | Info                              ")
    print("+".join(hyphen_list))

    for p in pcap_packets:
        sys.stdout.write("%7d|" % (p.index+1))
        sys.stdout.write(("%5s" % str(p.pcap_header.ts_sec)) + (".%06d" % (p.pcap_header.ts_usec))[:4] + '|')
        
        if p.pcap_data.eth_frame.eth_type_name == "IPv4":
            sys.stdout.write("%s|" % p.pcap_data.eth_frame.ip_packet.src_addr.rjust(17))
            sys.stdout.write("%s|" % p.pcap_data.eth_frame.ip_packet.dst_addr.rjust(17))
            sys.stdout.write("%s|" % str(p.pcap_data.eth_frame.ip_packet.length).rjust(5))
            sys.stdout.write(("%s|" % str(p.pcap_data.eth_frame.ip_packet.protocol_name)).rjust(16))
            sys.stdout.write("%s" % str("[Please wait for a while]"))
            sys.stdout.write('\n')
            #print("----------------------------------------------------------------------------------------------------")
        
        # Activate the following code if you want to display information of IPv6 and other Packet.
        """
        sys.stdout.write("%s|" % p.pcap_data.eth_frame.ip_packet.src_addr.rjust(17))
        sys.stdout.write("%s|" % p.pcap_data.eth_frame.ip_packet.dst_addr.rjust(17))
        sys.stdout.write("%s|" % str(p.pcap_data.eth_frame.ip_packet.length).rjust(5))
        sys.stdout.write(("%s|" % str(p.pcap_data.eth_frame.ip_packet.protocol_name)).rjust(16))
        sys.stdout.write("%s" % str("[Please wait for a while]"))
        sys.stdout.write('\n')
        #print("----------------------------------------------------------------------------------------------------")
        """

    sys.stdout.write('\n')    

    
        