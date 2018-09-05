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

def print_packet_roughly(pcap_packets: List[Pcap_packet]):
    print("---------+------------------+------------------+-----+----------+-----------------------------------")
    print("   Time  |       src        |       dst        | len | protocol | Info                              ")
    print("---------+------------------+------------------+-----+----------+-----------------------------------")

    for p in pcap_packets:
        sys.stdout.write(("%5s" % str(p.pcap_header.ts_sec)) + (".%03d" % (p.pcap_header.ts_usec))[:4])
        sys.stdout.write(' ')
        if p.pcap_data.eth_frame.eth_type_name == "IPv4":
            sys.stdout.write("%s" % p.pcap_data.eth_frame.ip_packet.src_addr.rjust(18))
            sys.stdout.write(' ')
            sys.stdout.write("%s" % p.pcap_data.eth_frame.ip_packet.dst_addr.rjust(18))
            sys.stdout.write(' ')
            sys.stdout.write("%s" % str(p.pcap_data.eth_frame.ip_packet.length).rjust(5))
            sys.stdout.write(' ')
            sys.stdout.write(("%s" % str(p.pcap_data.eth_frame.ip_packet.protocol)).rjust(10))
            sys.stdout.write(' ')
            sys.stdout.write("%s" % str("[Please wait for a while]"))
            sys.stdout.write('\n')
            print("----------------------------------------------------------------------------------------------------")

    sys.stdout.write('\n')    

    
        