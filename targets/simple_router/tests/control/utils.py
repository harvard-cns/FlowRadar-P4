import struct

def hex_to_i16(h):
    x = int(h)
    if (x > 0x7FFF): x-= 0x10000
    return x
def hex_to_i32(h):
    x = int(h)
    if (x > 0x7FFFFFFF): x-= 0x100000000
    return x
def hex_to_byte(h):
    x = int(h)
    if (x > 0x7F): x-= 0x100
    return x
def uint_to_i32(u):
    if (u > 0x7FFFFFFF): u-= 0x100000000
    return u

def bytes_to_string(byte_array):
    form = 'B' * len(byte_array)
    return struct.pack(form, *byte_array)

def macAddr_to_string(addr):
    byte_array = [int(b, 16) for b in addr.split(':')]
    return bytes_to_string(byte_array)

def ipv4Addr_to_i32(addr):
    byte_array = [int(b) for b in addr.split('.')]
    res = 0
    for b in byte_array: res = res * 256 + b
    return uint_to_i32(res)
