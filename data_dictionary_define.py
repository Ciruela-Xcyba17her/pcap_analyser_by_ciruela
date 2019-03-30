from tool_func import read_all_lines_from_file

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
TCP_PORTS = make_data_dic("tcp_port")
UDP_PORTS = make_data_dic("udp_port")
SCTP_PORTS = make_data_dic("sctp_port")
DCCP_PORTS = make_data_dic("dccp_port")

DEFINED_ETHTYPES = read_all_lines_from_file("defined_ethtypes")
DEFINED_IP_PROTOCOLS = read_all_lines_from_file("defined_ip_protocols")

if __name__=="__main__":
    """ Use this space you want to test something.
    LINK_TYPES = make_data_dic("link_types")
    ETH_TYPES = make_data_dic("eth_types")
    print(ETH_TYPES[2048])
    """

