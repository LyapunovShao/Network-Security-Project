
from SimpleRSA import RSA
from simple_aes_cipher import AESCipher, generate_secret_key
from Crypto.Cipher import AES
import binascii
from struct import pack
"""
R = RSA()

pk, sk = R.generate_key(1024)
p = 'Ruotong Gao'.encode('utf8')
print(R.decrypt(R.encrypt(p, pk), sk))
"""
"""
AES_key = generate_secret_key("123")
cipher = AESCipher(AES_key)

print(AES_key)

p = "Ruotong Gao"
c = cipher.encrypt(p)
"""


def int2bytes(num):
    max_uint = 0xffffffffffffffff
    raw_bytes = b''
    result = b''
    while num > 0:
        raw_bytes = raw_bytes + pack('Q', num & max_uint)
        num >>= 64
    last_ind = len(raw_bytes) - 1
    while last_ind >= 0 and raw_bytes[last_ind].to_bytes(1, byteorder='big') == b'\x00':
        last_ind -= 1

    while last_ind >= 0:
        result = result + \
            raw_bytes[last_ind].to_bytes(1, byteorder='big')
        last_ind -= 1
    return result


def bytes2int(b):
    return int(binascii.hexlify(b), 16)


def main():

    R = RSA()
    pk, sk = R.generate_key(1024)
    n, e = pk
    AES_key = b'abcdabcdabcdabcd'
    C = R.encrypt(AES_key, pk)
    b = 127
    while b >= 100:
        print("b = ", b, "\n")
        bkey = int2bytes(bytes2int(AES_key) << b)

        #print(R.encrypt(bkey ,pk))
        print("\n")
        print(bkey[len(bkey)-16:len(bkey)])

        print("\n")

        C_int = bytes2int(C)
        Cb = int2bytes((C_int*pow(2, b*e, n)) % n)
        # print(Cb)
        print("\n")
        key = R.decrypt(Cb, sk)
        key = key[len(key)-16:len(key)]
        print(key)

        b -= 1
        print("\n")


if __name__ == '__main__':
    main()
