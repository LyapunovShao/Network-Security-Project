
from SimpleRSA import RSA
from simple_aes_cipher import AESCipher, generate_secret_key
from Crypto.Cipher import AES

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
AES_key = b'1234123412341234'
cipher = AES.new(AES_key, AES.MODE_EAX)
print(cipher.encrypt(b'123'))