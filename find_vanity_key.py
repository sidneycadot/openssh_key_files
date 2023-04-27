#! /usr/bin/env -S python3 -B

"""Find a vanity key.

NOTE: This needs work.
"""

import io
import random
import base64
import math
from fractions import Fraction

from gmpy2 import is_prime

from rsa_math import modular_inverse
from openssh_key_types import PublicKey, write_public_key


def get_random_numbits_number(numbits: int) -> int:
    """Generate a random number of precisely 'numbits' bits."""
    return random.randrange(2 ** (numbits - 1), 2 ** numbits)


def main():
    """Main function."""

    suffix_string = "/Help+Help+We+are+being+held+prisoner+inside+an+OpenSSH+key+factory/"

    p_bits = 1536
    q_bits = 1536

    while True:
        p = get_random_numbits_number(p_bits)
        if is_prime(p):
            break

    print('p', p)

    suffix_string="/Een+van+de+priemfactoren+in+deze+overigens+prima+sleutel+is+{}".format(p)

    num_suffix_digits = len(suffix_string)

    suffix = int.from_bytes(base64.b64decode("A" * (-num_suffix_digits % 4) + suffix_string), byteorder='big')

    assert suffix % 2 != 0

    smallest_possible_prefix = (-suffix * modular_inverse(64 ** num_suffix_digits, p)) % p

    print("smallest_possible_prefix:", smallest_possible_prefix)

    # We want:
    #
    # 2**(q_bits - 1) <= q < 2^q_bits
    #
    # 2**(q_bits - 1) <= n/p < 2^q_bits
    #
    # 2**(q_bits - 1) * p <= n < (2^q_bits) * p
    #
    # 2**(q_bits - 1) * p <= (64 ** num_suffix_digits) * (smallest_possible_prefix + p * k) + suffix < (2^q_bits) * p
    #
    # 2**(q_bits - 1) * p - suffix <= (64 ** num_suffix_digits) * (smallest_possible_prefix + p * k) < (2^q_bits) * p - suffix
    #
    # (2^(q_bits - 1) * p - suffix) /  (64 ** num_suffix_digits) <= smallest_possible_prefix + p * k < ((2^q_bits) * p - suffix) /  (64 ** num_suffix_digits)
    #
    # (2^(q_bits - 1) * p - suffix) /  (64 ** num_suffix_digits) - smallest_possible_prefix <= p * k < ((2^q_bits) * p - suffix) /  (64 ** num_suffix_digits) - smallest_possible_prefix
    #
    # ((2^(q_bits - 1) * p - suffix) /  (64 ** num_suffix_digits) - smallest_possible_prefix) / p <= k < (((2^q_bits) * p - suffix) /  (64 ** num_suffix_digits) - smallest_possible_prefix) / p

    k_min = math.floor((Fraction(2**(q_bits - 1) * p - suffix) /  Fraction(64 ** num_suffix_digits) - smallest_possible_prefix) / p)
    k_max = math.ceil((Fraction((2**q_bits) * p - suffix) /  Fraction(64 ** num_suffix_digits) - smallest_possible_prefix) / p)

    print("k_min digits:", len(str(k_min)))
    print("k_max digits:", len(str(k_max)))

    k_min = 1
    k_max = 10**342

    with open("vanity_keys", "w", encoding='utf-8') as fo:

        zz1 = 0
        zz2 = 0
        zz3 = 0
        while True:

            zz1 += 1
            if zz1 % 10000 == 0:
                print(zz1, zz2, zz3)
            #k = random.randint(k_min, k_max)

            k = random.randint(k_min, k_max)
            assert k_min <= k <= k_max

            prefix = smallest_possible_prefix + p * k
            n = (64 ** num_suffix_digits) * prefix + suffix
            assert n % p == 0
            q = n // p

            if not is_prime(q):
                continue

            zz2 += 1

            public_key = PublicKey(65537, n, '')

            with io.StringIO() as f_test:
                write_public_key(f_test, public_key, end='')
                value = f_test.getvalue()

            if not value.endswith(suffix_string):
                continue

            zz3 += 1

            print(len(str(p)), len(str(q)), p, q, repr(value))

            print(value, file=fo)

    # Find a prefix for which the following holds:
    #
    #     prefix * 64**num_b64_suffix_digits + suffix == 0 (mod p)
    #
    #     prefix * 64**num_b64_suffix_digits == -suffix (mod p)
    #     prefix == -suffix * modular_inverse (mod p)

if __name__ == "__main__":
    main()
