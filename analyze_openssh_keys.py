#! /usr/bin/env python3

"""
The SSH public key format is documented in:

   The Secure Shell (SSH) Public Key File Format, RFC 4716, 2006
"""

import os
import base64
import struct


def read_fixed_size_field(b: bytes, size: int) -> tuple[bytes, bytes]:
    if len(b) < size:
        raise ValueError(f"Cannot read {size} bytes.")
    field = b[:size]
    b = b[size:]
    return (b, field)


def read_fixed_size_integer(b: bytes, size: int) -> tuple[bytes, int]:
    (b, field) = read_fixed_size_field(b, size)
    value = int.from_bytes(field, byteorder='big', signed=True)
    return (b, value)


def read_variable_size_field(b: bytes) -> tuple[bytes, bytes]:
    (b, size) = read_fixed_size_integer(b, 4)
    if size < 0:
        raise ValueError()
    (b, field) = read_fixed_size_field(b, size)
    return (b, field)


def read_variable_size_integer(b: bytes) -> tuple[bytes, int]:
    (b, size) = read_fixed_size_integer(b, 4)
    if size < 0:
        raise ValueError()
    return read_fixed_size_integer(b, size)


def read_public_key(filename) -> tuple[int, int]:

    with open(filename, "r") as fi:
        fields = next(fi).split()

    if len(fields) not in (3, 4):
        raise ValueError("Bad number of fields.")

    keyspec = fields[-2]

    b = base64.b64decode(keyspec)

    (b, field) = read_variable_size_field(b)
    if field != b"ssh-rsa":
        raise ValueError()

    (b, exponent) = read_variable_size_integer(b)
    if exponent < 0:
        raise ValueError("ssh-rsa exponent is negative.")
    
    (b, modulus) = read_variable_size_integer(b)
    if modulus <= 0:
        raise ValueError("modulus is not positive.")

    if len(b) != 0:
        raise ValueError("Not at end.")

    return (exponent, modulus)

def powermod(a, b, modulus):
    result = 1
    apow = a

    while b!= 0:
        if b % 2 != 0:
            result = (result * apow) % modulus
        b //= 2
        apow = (apow * apow) % modulus

    return result

def gcd(a, b):
    while a != 0:
        (a, b) = (b % a, a)
    return b

def lcm(a, b):
    return  a * b / gcd(a, b)

def read_private_key(filename):
    """
    openssh sshkey.c is 3666 lines.
    
    AUTH_MAGIC is used in:
    
    static int sshkey_private_to_blob2()     --     line 2739--2863
    static int private2_uudecode()           --     line 2865--2938
    static int private2_crypt()              --     line 2940--3085
    static int sshkey_parse_private2_pubkey  --     line 3147--3195
    

    """
    key_lines = None
    with open(filename, "r") as fi:
        for line in fi:
            line = line.strip()
            if line == '-----BEGIN OPENSSH PRIVATE KEY-----':
                assert key_lines is None
                key_lines = []
            elif line == '-----END OPENSSH PRIVATE KEY-----':
                assert key_lines is not None
            elif key_lines is not None:
                key_lines.append(line)

    assert key_lines is not None

    b = base64.b64decode("".join(key_lines))

    (b, auth_magic) = read_fixed_size_field(b, 15)
    assert auth_magic == b"openssh-key-v1\x00"

    (b, ciphername) = read_variable_size_field(b)
    assert ciphername == b"none"

    (b, kdfname) = read_variable_size_field(b)
    assert kdfname == b"none"

    (b, kdf) = read_variable_size_field(b)
    assert kdf == b""

    (b, number_of_keys) = read_fixed_size_integer(b, 4)
    assert number_of_keys == 1

    (b, b_pubkey) = read_variable_size_field(b)

    if True:
        (b_pubkey, pubkey_type) = read_variable_size_field(b_pubkey)
        assert pubkey_type == b"ssh-rsa"

        (b_pubkey, pubkey_rsa_e) = read_variable_size_integer(b_pubkey)
        if pubkey_rsa_e < 0:
            raise ValueError("ssh-rsa exponent is negative.")
        print("pubkey_rsa_e>", pubkey_rsa_e)
        print()

        (b_pubkey, pubkey_rsa_n) = read_variable_size_integer(b_pubkey)
        if pubkey_rsa_n < 0:
            raise ValueError("ssh-rsa modulus is negative.")
        print("pubkey_rsa_n>", pubkey_rsa_n)
        print()

        assert len(b_pubkey) == 0

    (b, b_privkey) = read_variable_size_field(b)

    if True:

        (b_privkey, privkey_salt1) = read_fixed_size_field(b_privkey, 4)
        (b_privkey, privkey_salt2) = read_fixed_size_field(b_privkey, 4)

        print("privkey_salt1>", privkey_salt1)
        print("privkey_salt2>", privkey_salt2)

        # sshkey_private_serialize_opt.

        (b_privkey, field12) = read_variable_size_field(b_privkey)            # L2448
        assert field12 == b"ssh-rsa"

        (b_privkey, privkey_rsa_n) = read_variable_size_integer(b_privkey)
        if privkey_rsa_n < 0:
            raise ValueError("ssh-rsa modulus is negative.")
        print("privkey_rsa_n>", privkey_rsa_n)
        print()

        (b_privkey, privkey_rsa_e) = read_variable_size_integer(b_privkey)
        if privkey_rsa_e < 0:
            raise ValueError("ssh-rsa exponent is negative.")
        print("privkey_rsa_e>", privkey_rsa_e)
        print()

        (b_privkey, privkey_rsa_d) = read_variable_size_integer(b_privkey)
        if privkey_rsa_d < 0:
            raise ValueError("ssh-rsa modulus is negative.")
        print("privkey_rsa_d>", privkey_rsa_d)
        print()

        (b_privkey, privkey_rsa_iqmp) = read_variable_size_integer(b_privkey)
        print("privkey_rsa_iqmp>", privkey_rsa_iqmp)
        print()

        (b_privkey, privkey_rsa_p) = read_variable_size_integer(b_privkey)
        print("privkey_rsa_p>", privkey_rsa_p)
        print()

        (b_privkey, privkey_rsa_q) = read_variable_size_integer(b_privkey)
        print("privkey_rsa_q>", privkey_rsa_q)
        print()

        (b_privkey, comment) = read_variable_size_field(b_privkey)
        print("comment", comment)
        print()

        padding = b_privkey

        assert padding == bytes(  [  (i + 1) % 256 for i in range(len(padding)) ])

    assert len(b) == 0

    assert pubkey_rsa_n == privkey_rsa_n
    assert pubkey_rsa_e == privkey_rsa_e

    assert privkey_rsa_n == privkey_rsa_p * privkey_rsa_q


def main():

    # Read public key data.

    public_key_filename = "testkey.pub"
    (e, m) = read_public_key(public_key_filename)
    print("public key -- e:", e)
    print("public key -- m:", m)

    private_key_filename = "testkey"
    read_private_key(private_key_filename)

if __name__ == "__main__":
    main()
