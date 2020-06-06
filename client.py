from SimpleRSA import RSA
from Crypto.Cipher import AES
from Crypto import Random
from time import sleep
from socket import *
HOST = '127.0.0.1'
PORT = 12321
BUF_SIZE = 2048
ADDR = (HOST, PORT)
AES_key = b'abcdabcdabcdabcd'                     # the client chooses this 128-bit AES key
WUP = "Ruotong Gao loves you"              # the client chooses this plain text to send
IV = b'\xd6V\xf45E\x8a\xeec\xf9\x98\x13bo\\\x8e ' # the initial vector for AES encryption

def main():
    # get the public key
    f = open("public_key", "r")
    n = int(f.readline())
    e = int(f.readline())
    pk = (n, e)

    # encrypting the AES key and the plain text 
    RSA_cipher = RSA()
    AES_cipher = AES.new(AES_key, AES.MODE_CFB, IV)
    cipher_AES_key = RSA_cipher.encrypt(AES_key, pk)
    cipher_WUP = AES_cipher.encrypt(WUP.encode('utf8'))
   

    # send the RSA encrypted AES_key and the AES encrypted WUP
    cliSocket = socket(AF_INET, SOCK_STREAM)
    cliSocket.connect(ADDR)
 
    cliSocket.sendall(cipher_AES_key)

    feed_back = cliSocket.recv(BUF_SIZE)
    if feed_back != b"OK":
        print("Error: server failed to receive the AES key")
        return 
    cliSocket.sendall(cipher_WUP)
   
    feed_back = cliSocket.recv(BUF_SIZE)
    print(feed_back)
    cliSocket.close()



if __name__ == "__main__":
    main()
