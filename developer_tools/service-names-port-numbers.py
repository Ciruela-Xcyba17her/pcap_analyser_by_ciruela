"""
Execute this program with data from next URL when you want to update port_dictionary from IANA.
https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv
"""

import sys
import os
import datetime

with open("service-names-port-numbers-copied.csv", 'r') as f:
    lines = f.readlines()

    f_port_data_last_updated_date = open("port_data_last_updated_date.txt",'w')
    f_tcp = open("tcp_port.csv",'w')
    f_udp = open("udp_port.csv",'w')
    f_sctp = open("sctp_port.csv",'w')
    f_dccp = open("dccp_port.csv",'w')

    tcp_list, udp_list, sctp_list, dccp_list = [], [], [], []
    latest_tcp_num = latest_udp_num = latest_sctp_num = latest_dccp_num = -1

    i = 0

    # read each line
    for line in lines[1:]:
        i += 1

        line_split = line.split(',')
        t, p_num, p_name = line_split[2], line_split[1], line_split[0]
        
        if t == "" or p_num == "" or p_name == "":
            continue
        
        capital_p_name = ""
        a_ord = ord('a')
        z_ord = ord('z')
        A_ord = ord('A')
        d = a_ord - A_ord

        for c in p_name:
            if a_ord <= ord(c) <= z_ord:
                capital_p_name += chr(ord(c) - d)
            else:
                capital_p_name += c
        p_name = capital_p_name

        if t == "tcp":
            if p_num == latest_tcp_num:
                continue
            latest_tcp_num = p_num
            tcp_list.append([p_num, p_name])
        elif t == "udp": 
            if p_num == latest_udp_num:
                continue
            latest_udp_num = p_num
            udp_list.append([p_num, p_name])
        elif t == "sctp": 
            if p_num == latest_sctp_num:
                continue
            latest_sctp_num = p_num
            sctp_list.append([p_num, p_name])
        elif t == "dccp": 
            if p_num == latest_dccp_num:
                continue
            latest_dccp_num = p_num
            dccp_list.append([p_num, p_name])
        else:
            print(i)
            print("[ ! ] UNKNOWN TYPE \"%s\"" % t)
            sys.exit(1)
    
    for l in tcp_list:
        f_tcp.write("%s,%s\n" % (l[0], l[1]))
    
    for l in udp_list:
        f_udp.write("%s,%s\n" % (l[0], l[1]))
    
    for l in sctp_list:
        f_sctp.write("%s,%s\n" % (l[0], l[1]))
    
    for l in dccp_list:
        f_dccp.write("%s,%s\n" % (l[0], l[1]))
    
    f_tcp.close()
    f_udp.close()
    f_sctp.close()
    f_dccp.close()

    print("[ + ] write_file finished successfully.")

    now = datetime.datetime.now()
    f_port_data_last_updated_date.write("Updated : %s" % now)
    f_port_data_last_updated_date.close()

    print("[ + ] Latest update time rewrited.")