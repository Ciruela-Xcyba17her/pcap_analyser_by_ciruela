# -*- coding:utf-8 -*-

def make_data_dic(csv_file):
    ret_dic = {}
    with open("data/%s.csv" % csv_file, 'r') as f:
        all_lines = f.readlines()

        for line in all_lines:
            num_hex_str, value = line.split(',')

            if num_hex_str.count('-'):
                start_key, end_key = [int(x, 16) for x in num_hex_str.split('-')]
                for i in range(end_key - start_key + 1):
                    ret_dic[start_key + i] = value.replace('\n', '')
            else:
                ret_dic[int(num_hex_str, 16)] = value.replace('\n', '')
    
    return ret_dic

LINK_TYPES = make_data_dic("link_types")
ETH_TYPES = make_data_dic("eth_types")
IPv4_PROTOCOLS = make_data_dic("ipv4_protocols")

if __name__=="__main__":
    LINK_TYPES = make_data_dic("link_types")
    ETH_TYPES = make_data_dic("eth_types")
    print(ETH_TYPES[2048])

