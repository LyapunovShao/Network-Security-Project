from SimpleRSA import RSA
from Crypto.Cipher import AES
from socket import *
HOST = ''
PORT = 12321
BUF_SIZE = 2048 * 1024
ADDR = (HOST, PORT)

# the initial vector for AES encryption
IV = b'\xd6V\xf45E\x8a\xeec\xf9\x98\x13bo\\\x8e '

def check_WUP(WUP):

    if WUP == "Ruotong Gao loves you":
        return True
    return False

def main():
    f = open("secret_key", "r")
    n = int(f.readline())
    e = int(f.readline())
    d = int(f.readline())
    p = int(f.readline())
    q = int(f.readline())
    sk = (n, e, d, p, q)

    # create ciphers
    RSA_cipher = RSA()

    # begin listening for information
    serSocket = socket(AF_INET, SOCK_STREAM)
    serSocket.bind(ADDR)
    serSocket.listen(5)

    while True:
        print("Waiting for connection...")
        cliSocket, addr = serSocket.accept()
        print("     Connected with ", addr)

        print("Begin receiving RSA encrypted AES key...")
        data = cliSocket.recv(BUF_SIZE)
        AES_key = RSA_cipher.decrypt(data, sk)
  
        AES_cipher = AES.new(AES_key, AES.MODE_CFB, IV)
        print("     AES key received")
        cliSocket.sendall(b"OK")
        print("Begin receiving AES encryted WUP...")
        data = cliSocket.recv(BUF_SIZE)
        WUP = AES_cipher.decrypt(data).decode('utf8')
        print(WUP)
        if check_WUP(WUP):
            cliSocket.sendall(b'Valid WUP')
        else:
            cliSocket.sendall(b'Invalid WUP')

        cliSocket.close()
        print("The current connection closed")

    serSocket.close()


if __name__ == "__main__":
    main()
