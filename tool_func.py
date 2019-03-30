from typing import List,Union



def my_struct_unpack_hex(endian, bit_list, bin_text, read_from = 0):
    cpy_bin_text = bin_text
    offset = read_from
    ret_bin_list = []

    for b in bit_list:
        extracted_bin = cpy_bin_text[offset : offset + b]
        ret_bin = int.from_bytes(extracted_bin, endian)
        ret_bin_list.append(ret_bin)
        offset += b
    
    return ret_bin_list


def my_struct_unpack_bin(endian, bit_range_list, bytes_text, read_from = 0):
    bit_text = format(int.from_bytes(bytes_text, "big"), 'b')
    bit_len = len(bit_text)
    bit_text = ('0' * (8 - bit_len % 8)) +  bit_text
    offset = read_from
    ret_dec_list = []
    bytes_length = []

    for bit_range in bit_range_list:
        ret_dec = int(bit_text[offset : offset + bit_range], 2)
        ret_dec_list.append(ret_dec)
        offset += bit_range
    
    if endian == "little":
        for i in range(len(ret_dec_list)):
            bytes_length = 1
            while True:
                if  (0x1 << (8 * bytes_length)) & ret_dec_list[i]:
                    break
                bytes_length += 1
            ret_dec_list[i] = int.from_bytes(ret_dec_list[i].to_bytes(bytes_length, 'little'), "big")

    return ret_dec_list

def print_irregal_param_found(cmd : List[Union[str, int]], target_index):
    print("%s: %s: Illegal parameter \"%s\"" % (cmd[0], cmd[target_index], cmd[target_index + 1]))
    
def equal_count(list : List[Union[int, str]], test_content):
    count = 0
    for s in list:
        if s == test_content:
            count += 1
    return count

def equal_index(list : List[Union[int, str]], test_content):
    for index, s in enumerate(list):
        if s == test_content:
            return index
    return 0

def read_all_lines_from_file(filename : str):
    with open("data/" + filename + ".txt") as f:
        lines = f.readlines()
        ret_lines = []
        for line in lines:
            ret_lines.append(line[:-1])
    return ret_lines

def read_ipv6_addr(plain_number:int):
    print("%x" % plain_number)
    ipv6_addr = []
    for i in range(8):
        addr = (plain_number >> ((8-i) * 16)) & 0xFFFF
        print("%04x" % addr)
        ipv6_addr.append("%04x" % addr)
    
    return ":".join(ipv6_addr)

# test function
if __name__=="__main__":
    print(read_ipv6_addr(111111111111111111))
    pass