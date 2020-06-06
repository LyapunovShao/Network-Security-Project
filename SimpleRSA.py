import math
import os
import binascii
from struct import pack

DEFAULT_E = 65537


def extended_gcd(a, b):
    """Returns a tuple (r, i, j) such that r = gcd(a, b) = ia + jb
    """
    # r = gcd(a,b) i = multiplicitive inverse of a mod b
    #      or      j = multiplicitive inverse of b mod a
    # Neg return values for i or j are made positive mod b or a respectively
    # Iterateive Version is faster and uses much less stack space
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a  # Remember original a/b to remove
    ob = b  # negative values from return results
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += ob  # If neg wrap modulo orignal b
    if ly < 0:
        ly += oa  # If neg wrap modulo orignal a
    return a, lx, ly  # Return only positive values


def random_int(nbits):
    """
        get a random int of nbits
    """
    nbytes, rbits = divmod(nbits, 8)

    # use the random source from os
    randomdata = os.urandom(nbytes)
    if rbits > 0:
        randomvalue = ord(os.urandom(1))
        randomvalue >>= (8 - rbits)
        randomdata = chr(randomvalue).encode('utf8') + randomdata
    value = int(binascii.hexlify(randomdata), 16)

    # make sure that the number is large enough to just fill
    # out the required number of bits
    value |= 1 << (nbits-1)
    return value


def random_int_max(maxvalue):
    """
        get a random int that 1<= value <= maxvalue
    """
    bits = 1+int(math.log2(maxvalue))
    tries = 0
    while True:
        value = random_int(bits)
        if value <= maxvalue:
            break

        # to increase the probability that value <= maxvalue
        if tries % 10 and tries:
            bits -= 1

        tries += 1
    return value


def miller_rabin_primality_testing(n, k):
    """
        calculates whether n is composite (which is always correct) or prime
    (which theoretically is incorrect with error probability 4**-k), by
    applying Miller-Rabin primality testing.
    """

    # prevent potential infinite loop when d = 0
    if n < 2:
        return False

    # decompose (n - 1) to write it as (2 ** r) * d
    # while d is even, divide it by 2 and increase the exponent.
    d = n - 1
    r = 0

    while not (d & 1):
        r += 1
        d >>= 1

    # test k witnesses.
    for _ in range(k):
        # generate random integer a, where 2 <= a <= (n - 2)
        a = random_int_max(n - 3) + 1

        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == 1:
                # n is composite.
                return False
            if x == n - 1:
                # exit inner loop and continue with next witness.
                break
        else:
            # if loop doesn't break, n is composite.
            return False

    return True


def is_prime(n):
    if n < 10:
        return n in {2, 3, 5, 7}
    if not (n & 1):
        return False
    bits = 1 + int(math.log2(n))
    if bits >= 1536:
        MR_rounds = 3
    elif bits >= 1024:
        MR_rounds = 4
    elif bits >= 512:
        MR_rounds = 7
    else:
        MR_rounds = 10

    return miller_rabin_primality_testing(n, MR_rounds+1)


def get_prime(nbits):
    assert nbits > 3
    while True:
        value = random_int(nbits) | 1

        if is_prime(value):
            return value


class RSA:

    def __init__(self):
        pass

    def generate_p_q(self, nbits):
        total_bits = 2 * nbits

        # shift some bits of p and q
        shift = nbits // 16
        pbits = nbits + shift
        qbits = nbits - shift

        def acceptable(p, q):
            """
                True iff p !=q and (p*q) has the right number bits
            """
            if p == q:
                return False
            return 1+int(math.log2(p*q)) == total_bits

        p = get_prime(pbits)
        q = get_prime(qbits)

        change_p = False
        while not acceptable(p, q):
            # change p or q in a turn
            if change_p:
                p = get_prime(pbits)
            else:
                q = get_prime(qbits)
            change_p = not change_p

        return max(p, q), min(p, q)

    def generate_e_d(self, p, q):
        phi_n = (p-1)*(q-1)
        (divider, inv, _) = extended_gcd(DEFAULT_E, phi_n)
        e = DEFAULT_E
        d = inv
        assert divider == 1
        assert (e*d) % phi_n == 1
        return e, d

    def generate_key(self, nbits):
        assert nbits >= 16
        (p, q) = self.generate_p_q(nbits//2)

        (e, d) = self.generate_e_d(p, q)
        n = p*q
        return (
            (n, e),
            (n, e, d, p, q)
        )

    def encrypt(self, text, pk):
        """
            text must be the binary expression of the 
            original text string, pk is the public key
        """
        n, e = pk
        text_int = int(binascii.hexlify(text), 16)
        assert text_int >= 0 and text_int <= n
        raw_bytes = b''
        result = b''
        num = pow(text_int, e, n)

        max_uint = 0xffffffffffffffff

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

    def decrypt(self, ciphertext, sk):
        n, e, d, p, q = sk
        ciphertext_int = int(binascii.hexlify(ciphertext), 16)

        assert ciphertext_int >= 0 and ciphertext_int <= n
        raw_bytes = b''
        result = b''
        num = pow(ciphertext_int, d, n)
        max_uint = 0xffffffffffffffff

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
