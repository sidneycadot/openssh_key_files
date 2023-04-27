#! /usr/bin/env -S python3 -B

"""Find a short, easy-to-remember key.

NOTE: This needs work.
"""

import io
import base64

from gmpy2 import is_prime

from openssh_key_types import PublicKey, write_binary_public_key


def count_end_character(s: str) -> int:
    """Find the number of identical characters at the end of the string."""
    if len(s) == 0:
        raise ValueError()
    last_character = s[-1]
    for size in range(len(s), 0, -1):
        if s.endswith(size * last_character):
            return size
    raise RuntimeError()


def find_working_key():
    """Find a short but valid key."""

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

    for p in range(191, 1000000000):
        if not is_prime(p):
            continue

        for num_triplets in (43, ):
            highbits_multiplier = 0x1000000 ** num_triplets
            highbits_multiplier_modulo_p = highbits_multiplier % p
            highbits_multiplier_modulo_2 = highbits_multiplier % 2
            triplet_multiplier = ((0x1000000 ** num_triplets - 1) // (0x1000000 - 1)) * (64 ** 3 + 64 ** 2 + 64 ** 1 + 64 ** 0)
            print("progress:", p, num_triplets)
            for triplet_character_index in range(64):
                n_candidate_lo = triplet_character_index * triplet_multiplier
                n_candidate_lo_modulo_p = n_candidate_lo % p
                n_candidate_lo_modulo_2 = n_candidate_lo % 2
                for high_bits in range(256, 32768):

                    n_candidate_hi_modulo_p = high_bits * highbits_multiplier_modulo_p
                    n_candidate_mod_p = (n_candidate_hi_modulo_p + n_candidate_lo_modulo_p) % p
                    if n_candidate_mod_p != 0:  # divisible by p!
                        continue

                    n_candidate_hi_modulo_2 = high_bits * highbits_multiplier_modulo_2
                    n_candidate_modulo_2 = (n_candidate_hi_modulo_2 + n_candidate_lo_modulo_2) % 2
                    if n_candidate_modulo_2 == 0:
                        continue

                    n_candidate_hi = high_bits * highbits_multiplier
                    n_candidate = n_candidate_hi + n_candidate_lo

                    assert n_candidate % 2 != 0
                    assert n_candidate % p == 0

                    if n_candidate < min_n:
                        continue

                    q = n_candidate // p
                    if not is_prime(q):
                        continue

                    e = 65537

                    public_key = PublicKey(
                        n = p * q,
                        e = e,
                        comment = ''
                    )

                    with io.BytesIO() as fo:
                        write_binary_public_key(fo, public_key)
                        blob =fo.getvalue()
                    public_key_base64 = base64.b64encode(blob).decode('ascii')

                    count_end_characters = count_end_character(public_key_base64)

                    if count_end_characters < 174:
                        continue

                    print("p", p, "q", q, "end", count_end_characters)
                    print(public_key_base64)
                    print("---------------")


def main():
    """Main function."""
    find_working_key()

if __name__ == "__main__":
    main()
