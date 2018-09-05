
def int_to_float(d):
    print("d="+str(d))
    base = 1
    ret_d = 0

    for i in range(64):
        base /= 2
        if d << i & 0x8000 == 0x8000:
            ret_d += base
    
    return ret_d


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

# test function
if __name__=="__main__":
    pass