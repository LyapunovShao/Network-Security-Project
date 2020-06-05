"""
import rsa

(pk, sk) = rsa.newkeys(512)
p = 'Ruotong Gao'.encode('utf8')
c = rsa.encrypt(p, pk)
p2 = rsa.decrypt(c, sk).decode('utf8')
print(p2)
"""

from SimpleRSA import RSA 
R=RSA()
pk, sk = R.generate_key(128)
p = 'Ruotong Gao'.encode('utf8')
print(R.decrypt(R.encrypt(p,pk), sk))
"""
import binascii
from SimpleRSA import RSA 
from struct import pack
R = RSA()
pk, sk = R.generate_key(32)
n, e = pk
text = "Ruotong Gao".encode('utf8')
text_int = int(binascii.hexlify(text), 16)
raw_bytes = b''
result = b''
num = pow(text_int, e, n)
print(num)
max_uint = (1 << 63)-1
while num > 0:
    raw_bytes = raw_bytes + pack('Q', num & max_uint)
    num >>= 64
last_ind = len(raw_bytes) - 1
while last_ind >= 0:
    if raw_bytes[last_ind].to_bytes(1, byteorder='big') != b'\x00' :
        result = result + raw_bytes[last_ind].to_bytes(1, byteorder='big')
    last_ind -= 1
print(raw_bytes)
print(result)
"""