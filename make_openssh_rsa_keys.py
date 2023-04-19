#! /usr/bin/env -S python3 -u

import math
from typing import NamedTuple, Optional, BinaryIO

from gmpy2 import is_prime

def extended_gcd(a, b) -> Tuple[int, int, int]:
    (gcd, r) = (a, b)  # becomes gcd(a, b)
    (ac, s) = (1, 0)   # the coefficient of a
    (bc, t) = (0, 1)   # the coefficient of b
    while r != 0:
        q = gcd // r
        (gcd, r) = (r, gcd % r)
        (ac, s) = (s, ac - q * s)
        (bc, t) = (t, bc - q * t)

    # Reduce ac and bc in this way so that ac is positive and bc is negative.

    ac %= ( b // gcd)
    bc %= (-a // gcd)

    return (ac, bc, gcd)


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

    find_working_key()

if __name__ == "__main__":
    main()
