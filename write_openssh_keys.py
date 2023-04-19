#! /usr/bin/env -S python3 -u

import math
import base64
import io
from typing import NamedTuple, Optional, BinaryIO

from gmpy2 import is_prime

def write_fixed_size_integer(fo: BinaryIO, n: int, size: int) -> None:
    blob = n.to_bytes(length=size, byteorder='big', signed=False)
    fo.write(blob)


def write_variable_size_blob(fo: BinaryIO, blob: bytes) -> None:
    blob_size = len(blob)
    write_fixed_size_integer(fo, blob_size, 4)
    fo.write(blob)


def write_variable_size_string(fo: BinaryIO, s: str) -> None:
    blob = s.encode('utf-8')
    write_variable_size_blob(fo, blob)


def write_variable_size_integer(fo: BinaryIO, n: int) -> None:
    # We cannot just use int.to_bytes, because for large numbers we get an OverflowError.
    octets = []
    while n != 0:
        octets.append(n % 0x100)
        n //= 0x100
    if len(octets) != 0 and octets[-1] > 0x7f:
        octets.append(0)
    blob = bytes(reversed(octets))
    write_variable_size_blob(fo, blob)


class openssh_rsa_key(NamedTuple):
    n: int
    e: int
    d: int
    iqmp: int
    p: int
    q: int
    comment: str

    def encode_public_key(self) -> bytes:
        with io.BytesIO() as fo:
            write_variable_size_string(fo, "ssh-rsa")
            write_variable_size_integer(fo, self.e)
            write_variable_size_integer(fo, self.n)
            return fo.getvalue()

    def encode_private_key(self, check: int, cipher_blocksize: int) -> bytes:

        with io.BytesIO() as fo:
            write_fixed_size_integer(fo, check, 4)
            write_fixed_size_integer(fo, check, 4) # Same 'check' value is repeated twice.
            write_variable_size_string(fo, "ssh-rsa")
            write_variable_size_integer(fo, self.n)
            write_variable_size_integer(fo, self.e)
            write_variable_size_integer(fo, self.d)
            write_variable_size_integer(fo, self.iqmp)
            write_variable_size_integer(fo, self.p)
            write_variable_size_integer(fo, self.q)
            write_variable_size_string(fo, self.comment)


            padding_size = -len(fo.getbuffer()) % cipher_blocksize
            padding = bytes((i + 1) % 0x100 for i in range(padding_size))
            fo.write(padding)

            return fo.getvalue()

    def encode_private_key_file_data(self, check: int) -> bytes:

        auth_magic = b"openssh-key-v1\x00"
        ciphername = "none"
        kdfname = "none"
        kdf = ""
        number_of_keys = 1

        cipher_blocksize = 64

        with io.BytesIO() as fo:

            fo.write(auth_magic)
            write_variable_size_string(fo, ciphername)
            write_variable_size_string(fo, kdfname)
            write_variable_size_string(fo, kdf)
            write_fixed_size_integer(fo, number_of_keys, 4)

            encoded_public_key = self.encode_public_key()
            write_variable_size_blob(fo, encoded_public_key)

            encoded_private_key = self.encode_private_key(check, cipher_blocksize)
            write_variable_size_blob(fo, encoded_private_key)

            return fo.getvalue()

    def get_public_key_file_contents(self) -> str:
        encoded_public_key = self.encode_public_key()
        encoded_public_key_base64 = base64.b64encode(encoded_public_key).decode('ascii')

        public_key_file_contents = "ssh-rsa " + encoded_public_key_base64

        if len(self.comment) != 0:
            public_key_file_contents += (" " + self.comment)

        return public_key_file_contents

    def get_private_key_file_contents(self, check: Optional[int]=None) -> str:

        if check is None:
            check = 0

        encoded_private_key = self.encode_private_key_file_data(check)

        encoded_private_key_base64 = base64.b64encode(encoded_private_key).decode('ascii')

        max_line_length = 70

        with io.StringIO() as fo:
            print("-----BEGIN OPENSSH PRIVATE KEY-----", file=fo)
            offset = 0
            while offset < len(encoded_private_key_base64):
                print(encoded_private_key_base64[offset:offset + max_line_length], file=fo)
                offset += max_line_length
            print("-----END OPENSSH PRIVATE KEY-----", file=fo, end='')

            return fo.getvalue()



def calculate_d(e: int, p: int, q: int):
    totient = math.lcm(p - 1, q - 1)
    return extended_gcd(e, totient)[0]

def count_end_character(s):
    last_character = s[-1]
    for size in range(len(s), 0, -1):
        if s.endswith(size * last_character):
            return size
    raise RuntimeError()

def find_working_key():
    # |ZZZ|Zsh|a-r|saZ|ZZZ|eee|ZZZ|Znn|nnn|nnn|nnn|nnn|nnn|nnn|nnn
    # AAAA
    #     B3Nz
    #         aC1y
    #             c2EA
    #                 AAAD
    #                     AQAB

    # 17 * (2 ** 18 + 2 ** 12 + 2 ** 6 + 2 ** 0)

    # AAAA.B3Nz.aC1y.c2EA.AAAD.AQAB.AAAA.gg48.8888.88
    # AAAA.B3Nz.aC1y.c2EA.AAAD.AQAB.AAAA.ggQk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkkk.kkk=
    #                                           1   2    3    4    5    6     7    8   9    10    11   12   13   14  15   16   17   18   19   20   21   22   23   24   25   26   27   28   29   30   31   32   33   34   35   36   37   38   39   40   41   42
    min_n = 2**1024

    for num_triplets in (43, ):
        triplet_multiplier = ((0x1000000 ** num_triplets - 1) // (0x1000000 - 1)) * (64 ** 3 + 64 ** 2 + 64 ** 1 + 64 ** 0)
        for high_bits in range(256, 32768):
            highbits_multiplier = 0x1000000 ** num_triplets
            for triplet_character_index in range(64):
                n_candidate = high_bits * highbits_multiplier + triplet_character_index * triplet_multiplier

                if n_candidate % 2 == 0:
                    continue

                if n_candidate < min_n:
                    continue

                for p in range(3, 10000, 2):
                    if is_prime(p):
                        if n_candidate % p == 0:
                            q = n_candidate // p
                            if is_prime(q):

                                e = 65537
                                d = calculate_d(e, p, q)

                                key = openssh_rsa_key(
                                        n = p * q,
                                        e = e,
                                        d = d,
                                        iqmp = 1, # invalid
                                        p = p,
                                        q = q,
                                        comment = ''
                                    )

                                public_key_file_contents = key.get_public_key_file_contents()

                                count_end_characters = count_end_character(public_key_file_contents)

                                if count_end_characters >= 174:

                                    print("p", p, "q", q, "end", count_end_characters)
                                    print(public_key_file_contents)
                                    print("---------------")

def main():

    #find_working_key()
    #return

    # Data for an example key that was generated using ssh-keygen.
    # Requirements:
    #   e must be at least 1, and at least 32768 to work.
    #   d must be at least 128.
    #   iqmp may be 1.
    #   p and q may both be 3.

    #p = 181
    #q = 1053360207830926069375087745573616386928165832017970323281724485015791148524103512468214471698148024799365213452379813959951740523818649570155405939279759983725768619405052377814733763472494871935927141149391541300595446460702797499654562693492582011602773631667220740436754817559016111955088938745959147588549

    p = 193
    q = 1999895600616818995961412498117001558360788665997299443446632492855213428426707636434060139556697407625938296289933660236915419453946919848735154073402255227256925957187881889176068758323621428240361298818484071401382927625260549077569397062258503287574460715257545713624423810599322526813357675732484127634574979

    #p = 2**512
    #q = 2**512
    e = 65537

    #while not is_prime(p):
    #    p += 1

    #while not is_prime(q):
    #    q -= 1

    d = calculate_d(e, p, q)

    key = openssh_rsa_key(
            n = p * q,
            e = e,
            d = d,
            iqmp = 1, # invalid
            p = 3,
            q = 3,
            comment = ''
        )

    # Write public key.
    public_key_file_contents = key.get_public_key_file_contents()
    with open("regenerate_key.pub", "w") as fo:
        print(public_key_file_contents, file=fo)

    # Write private key.
    check = 0xab78db12  # This is a 32-bit random value that is stored inside the private key file prior to encryption.
    private_key_file_contents = key.get_private_key_file_contents(check)
    with open("regenerate_key", "w") as fo:
        print(private_key_file_contents, file=fo)




    # AAAAB3NzaC1yc2EAAAADAQABAAAAgQD//////////
if __name__ == "__main__":
    main()
