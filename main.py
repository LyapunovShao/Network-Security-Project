
from SimpleRSA import RSA, is_prime
import binascii
R = RSA()

pk, sk = R.generate_key(1024)
p = 'Ruotong Gao'.encode('utf8')
print(R.decrypt(R.encrypt(p, pk), sk))


