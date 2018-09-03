def int_to_float(d):
    base = 1
    ret_d = 0

    for i in range(32):
        base /= 2
        if d << i & 0x8000 == 0x8000:
            ret_d += base
    
    return ret_d

if __name__=="__main__":
    print(int_to_float(0x5800))