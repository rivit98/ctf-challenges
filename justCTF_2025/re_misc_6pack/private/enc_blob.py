from Crypto.Cipher import ARC4
import sys

inf,out,key = sys.argv[1:4]
print(inf,out,key)

key = int(key).to_bytes(length=2, byteorder='little')
plaintext = open(inf, 'rb').read()

cipher = ARC4.new(key)
ciphertext = cipher.encrypt(plaintext)

open(out, 'wb').write(ciphertext)
