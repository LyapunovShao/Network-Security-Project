from SimpleRSA import RSA

plain_text = "Miss Gao loves me"


def main():
    RSA_cipher = RSA()
    pk, sk = RSA_cipher.generate_key(1024)

    print("\nTask 1:\n")
    print("The plain text: " + plain_text)
    print("\nThe generated keys --- (public key, secret key): \n")
    print((pk, sk))

    encrypted_text = RSA_cipher.encrypt(plain_text.encode('utf8'), pk)
    print("\nThe encrypted text(in byte form): \n")
    print(encrypted_text)

    decrypted_text = RSA_cipher.decrypt(encrypted_text, sk)
    print("\nThe decrypted text(in text form): \n")
    print(decrypted_text.decode('utf8'))


if __name__ == '__main__':
    main()
