"""
RSA crypto module
implements RSA from scratch for secure chat
no external crypto libraries used
"""

import random
import hashlib
import json
import base64
import struct
import os


# number theory stuff

def is_prime(n, k=20):
    """miller-rabin primality test
    checks if n is probably prime using k rounds
    more rounds = less chance of error (4^-k)
    based on the idea that for prime p: a^(p-1) = 1 mod p (fermat)
    and the only square roots of 1 mod p are 1 and -1
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # test with random witnesses
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)  # modular exponentiation built into python

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # composite for sure

    return True  # probably prime


def generate_prime(bits):
    """generate random prime with given bit length
    just keeps trying random odd numbers until one passes miller-rabin
    """
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1  # set high bit and make odd
        if is_prime(n):
            return n


def gcd(a, b):
    """euclidean algorithm for GCD"""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """extended euclidean - returns (gcd, x, y) where ax + by = gcd"""
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inverse(e, phi):
    """find d such that e*d = 1 mod phi using extended euclidean"""
    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        raise ValueError("inverse doesnt exist")
    return x % phi


# RSA key generation

def generate_keypair(bits=1024):
    """generate RSA public and private key pair
    1. pick two big primes p, q
    2. n = p*q
    3. phi = (p-1)(q-1)  euler totient
    4. e = 65537  standard public exponent
    5. d = inverse of e mod phi  private exponent
    returns (public_key, private_key) as tuples (exponent, n)
    """
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q:
        q = generate_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    # 65537 is standard choice - prime with only two 1-bits in binary so its fast
    e = 65537
    assert gcd(e, phi) == 1

    d = mod_inverse(e, phi)
    assert (e * d) % phi == 1  # sanity check

    return (e, n), (d, n)


# RSA encrypt/decrypt

def rsa_encrypt(m, public_key):
    """encrypt single number: c = m^e mod n"""
    e, n = public_key
    if m >= n:
        raise ValueError("message must be smaller than n")
    return pow(m, e, n)


def rsa_decrypt(c, private_key):
    """decrypt single number: m = c^d mod n"""
    d, n = private_key
    return pow(c, d, n)


def rsa_encrypt_bytes(data, public_key):
    """encrypt bytes with RSA by splitting into blocks
    each block gets a length byte prepended so we know the size when decrypting
    """
    e, n = public_key
    max_block = (n.bit_length() - 1) // 8 - 1  # max bytes per block

    encrypted_blocks = []
    for i in range(0, len(data), max_block):
        block = data[i:i + max_block]
        padded = bytes([len(block)]) + block  # prepend length
        m = int.from_bytes(padded, 'big')
        c = rsa_encrypt(m, public_key)
        encrypted_blocks.append(c)

    return encrypted_blocks


def rsa_decrypt_bytes(encrypted_blocks, private_key):
    """decrypt RSA blocks back to bytes"""
    result = b''
    for c in encrypted_blocks:
        m = rsa_decrypt(c, private_key)
        byte_length = (m.bit_length() + 7) // 8
        padded = m.to_bytes(byte_length, 'big')
        actual_length = padded[0]  # first byte tells us the real data length
        result += padded[1:1 + actual_length]

    return result


# symmetric encryption - simple XOR cipher

def symmetric_encrypt(data, key):
    """XOR each byte of data with corresponding key byte (key repeats)
    simple but works - XOR is self-inverse so same function encrypts and decrypts
    """
    encrypted = bytearray()
    for i, byte in enumerate(data):
        encrypted.append(byte ^ key[i % len(key)])
    return bytes(encrypted)


def symmetric_decrypt(data, key):
    """same as encrypt because XOR is its own inverse"""
    return symmetric_encrypt(data, key)


# message integrity - SHA256 hashing

def compute_hash(data):
    """SHA256 hash of bytes - returns hex string
    even 1 bit change gives completely different hash (avalanche effect)
    """
    return hashlib.sha256(data).hexdigest()


def verify_integrity(data, expected_hash):
    """check if data matches the expected hash
    returns True if message wasnt tampered with
    """
    return compute_hash(data) == expected_hash


# network helpers - sending/receiving messages over sockets

def send_message(sock, data):
    """send JSON message with 4-byte length prefix
    need this because TCP is a stream - no message boundaries
    """
    payload = json.dumps(data).encode('utf-8')
    length = struct.pack('!I', len(payload))
    sock.sendall(length + payload)


def receive_message(sock):
    """receive JSON message with length prefix - returns dict or None"""
    raw_length = _recv_exactly(sock, 4)
    if not raw_length:
        return None

    length = struct.unpack('!I', raw_length)[0]

    payload = _recv_exactly(sock, length)
    if not payload:
        return None

    return json.loads(payload.decode('utf-8'))


def _recv_exactly(sock, n):
    """helper to read exactly n bytes from socket (TCP might give us chunks)"""
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def generate_symmetric_key(length=32):
    """random bytes for symmetric key - os.urandom is crypto-safe"""
    return os.urandom(length)
