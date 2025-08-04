#!/usr/bin/env python3

from scapy.all import *
import zlib
import base64
import lief
from Crypto.Cipher import ARC4
from capstone import *
from multiprocessing import Pool
import string
import hashlib

src='fd93:5ffa:ad0::2'

DATA_SIZE_BITS = 16
DATA_SIZE_BYTES = 2
START = 1 << DATA_SIZE_BITS
STOP = 1<<DATA_SIZE_BITS | 1

scapy_cap = rdpcap('dump.pcapng')

chunks = []
for pkt in scapy_cap:
    if IPv6 not in pkt: continue
    pkt = pkt[IPv6]

    if pkt.plen != 40: continue
    if pkt.src != src: continue
    chunks.append(pkt.payload.fl)

messages = []
msg_chunks = None
for msg in chunks:
    if msg == START:
        msg_chunks = []
    elif msg == STOP:
        messages.append(msg_chunks)
    else:
        msg_chunks.append(msg)

def decompress(arr):
    try:
        plain = zlib.decompress(arr, wbits = -zlib.MAX_WBITS)
        return plain
    except Exception as e:
        plain = zlib.decompress(arr[:-1], wbits = -zlib.MAX_WBITS)
        return plain

file = []
data_start = False
for msg in messages:
    arr = bytearray()
    for v in msg:
        arr.extend(v.to_bytes(2, byteorder='little'))

    plain = decompress(arr).decode()

    if 'uncompressed file checksum crc32' in plain:
        data_start = False

    if data_start:
        file.append(plain)
    else:
        print(plain)

    if 'going to send it in chunks' in plain:
        data_start = True


chunks = [base64.b64decode(d) for d in file]
d = b''.join(chunks)

with open("/tmp/decoded", "wb") as f:
    f.write(d)
    checksum = zlib.crc32(d) & 0xffffffff
    checksum = hex(checksum)
    print(checksum)

stage2 = open("./stage2.exe", "rb").read()
assert stage2 == d


binary = lief.parse("./6-pack")
sc = binary.get_section(".go.runtimeinfo").content
sc = bytes(sc)

# try to decrypt rc4 by bruting the key - we know the conditions - there are 1024 possibilities, so easy to figure out which one is valid one
# for k in range(0x10000):
#     if (k >> 11) != 0xf or k & 0x1 == 0: continue
#     # if k != 31337: continue

#     cipher = ARC4.new(k.to_bytes(2, byteorder='little'))
#     dec = cipher.decrypt(sc)

#     md = Cs(CS_ARCH_X86, CS_MODE_64)
#     for i in md.disasm(dec, 0):
#         print(i)

#     md = Cs(CS_ARCH_X86, CS_MODE_32)
#     for i in md.disasm(dec, 0):
#         print(i)


k = 31337
cipher = ARC4.new(k.to_bytes(2, byteorder='little'))
dec = cipher.decrypt(sc)
sc_dexored = bytes([x ^ 0x17 for x in dec[0x100:]])

hashes = [
    sc_dexored[0x2d0+i*0x20:0x2d0+(i+1)*0x20] for i in range(0xc)
]

alphabet = string.printable

def worker(expected):
    for c1 in alphabet:
        for c2 in alphabet:
            for c3 in alphabet:
                s = c1+c2+c3
                if hashlib.sha256(s.encode()).digest() == expected:
                    return s


flag = []
with Pool() as p:
    for part in p.map(worker, hashes):
        flag.append(part)

print(''.join(flag)[::-1])