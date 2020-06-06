from SimpleRSA import RSA
from Crypto.Cipher import AES
from socket import *
from struct import pack
import binascii
HOST = '127.0.0.1'
CLI_PORT = 12321
SER_PORT = 12322
BUF_SIZE = 2048 * 1024
CLI_ADDR = (HOST, CLI_PORT)
SER_ADDR = (HOST, SER_PORT)
# the client chooses this plain text to send
WUP = "Miss Gao loves you"
# the initial vector for AES encryption
IV = b'\xd6V\xf45E\x8a\xeec\xf9\x98\x13bo\\\x8e '


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


def main():
    # get the public key
    f = open("public_key", "r")
    n = int(f.readline())
    e = int(f.readline())
    pk = (n, e)
    f = open("secret_key", "r")
    n = int(f.readline())
    e = int(f.readline())
    d = int(f.readline())
    p = int(f.readline())
    q = int(f.readline())
    f.close()
    sk = (n, e, d, p, q)
    RSA_cipher = RSA()

    # begin listening to the client and connect to the server
    cliSocket = socket(AF_INET, SOCK_STREAM)
    serSocket = socket(AF_INET, SOCK_STREAM)

    print("Connecting to the server...")
    serSocket.connect(SER_ADDR)
    print("Done")

    print("Waiting for the client...")
    cliSocket.bind(CLI_ADDR)
    cliSocket.listen(5)
    received_client, addr = cliSocket.accept()
    print("     Connected with client ", addr)

    # begin listening to the communication

    # AES key
    data = received_client.recv(BUF_SIZE)
    C = data
    serSocket.sendall(data)

    # Server feedback
    data = serSocket.recv(BUF_SIZE)
    received_client.sendall(data)

    # WUP
    data = received_client.recv(BUF_SIZE)
    serSocket.sendall(data)

    # Server feedback
    data = serSocket.recv(BUF_SIZE)
    received_client.sendall(data)

    # the true communication between client and server ends
    cliSocket.close()
    serSocket.close()
    received_client.close()
    # now pretend to be the client
    # query the server for 128 times to carry out CCA2 attack

    b = 127
    guessed_key = 0
    while b >= 0:
        print("\nb = ", b)
        # compute Cb by the equation in the paper
        C_int = int(binascii.hexlify(C), 16)
        Cb = int2bytes((C_int*pow(2, b * e, n)) % n)

        # guess the highest bit to be 1, and encrypt
        # a valid WUP with our guessed AES key
        guessed_key >>= 1
        guessed_key |= (1 << 127)
        guessed_key_bytes = int2bytes(guessed_key)
        while len(guessed_key_bytes) < 16:
            guessed_key_bytes = b'\x00'+guessed_key_bytes
        AES_cipher = AES.new(guessed_key_bytes, AES.MODE_CFB, IV)
        cipher_WUP = AES_cipher.encrypt(WUP.encode('utf8'))

        # begin a new connection to the server
        serSocket = socket(AF_INET, SOCK_STREAM)
        serSocket.connect(SER_ADDR)

        # send the encryption of the shifted AES key
        serSocket.sendall(Cb)

        # receive the feed back
        feed_back = serSocket.recv(BUF_SIZE)
        if feed_back != b"OK":
            print("Error: server failed to receive the AES key")
            return
        # send the encryptd WUP
        serSocket.sendall(cipher_WUP)
        feed_back = serSocket.recv(BUF_SIZE)

        # check the feedback of the server, if 
        # it refuses and return invalid WUP, 
        # we know the highest bit should be 0
        if feed_back == b'Invalid WUP':
            guessed_key -= (1 << 127)

        # if it accepts and return valid WUP,
        # we know the highest bit should be 1

        b -= 1
        print("\nCurrent guessed key: ")
        print(int2bytes(guessed_key))
        serSocket.close()
    
    # show the guessed key
    print("\nThe cracked AES key: ")
    print(int2bytes(guessed_key))


if __name__ == '__main__':
    main()
