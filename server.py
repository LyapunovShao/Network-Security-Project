from SimpleRSA import RSA
from Crypto.Cipher import AES
from socket import *
HOST = ''
PORT = 12322
BUF_SIZE = 2048 * 1024
ADDR = (HOST, PORT)

# the initial vector for AES encryption
IV = b'\xd6V\xf45E\x8a\xeec\xf9\x98\x13bo\\\x8e '


def check_WUP(WUP):

    if WUP == "Miss Gao loves you":
        return True
    return False


def main():
    # get the secret key5
    f = open("secret_key", "r")
    n = int(f.readline())
    e = int(f.readline())
    d = int(f.readline())
    p = int(f.readline())
    q = int(f.readline())
    f.close()
    sk = (n, e, d, p, q)

    # create ciphers
    RSA_cipher = RSA()

    # begin listening to information
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

        # get the lower 128 bits as the AES key
        AES_key = AES_key[len(AES_key)-16:len(AES_key)]

        AES_cipher = AES.new(AES_key, AES.MODE_CFB, IV)
        print("     AES key received")
        cliSocket.sendall(b"OK")
        print("Begin receiving AES encryted WUP...")

        data = cliSocket.recv(BUF_SIZE)

        try:
            WUP = AES_cipher.decrypt(data).decode('utf8')

            if check_WUP(WUP):
                print("Valid WUP")
                cliSocket.sendall(b'Valid WUP')
            else:
                print("Invalid WUP")
                cliSocket.sendall(b'Invalid WUP')

        except UnicodeDecodeError:
            print("Invalid WUP")
            cliSocket.sendall(b'Invalid WUP')

        cliSocket.close()
        print("The current connection closed")

    serSocket.close()


if __name__ == "__main__":
    main()
