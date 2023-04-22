#! /usr/bin/env python3

import random
import base64
from gmpy2 import is_prime

def next_prime(p: int):
    while True:
        p += 1
        if is_prime(p):
            break
    return p

suffix_string = "/Help+Help+We+are+being+held+prisoner+inside+an+OpenSSH+key+factory/"

#num_b64_prefix_digits = 100 + (-len(suffix) % 4)

suffix_digits = len(suffix)

suffix = int.from_bytes(base64.b64decode("A" * (-len(suffix) % 4) + suffix), byteorder='big')

p_bits = 20
while True:
    p = random.randrange(2 ** (p_bits - 1), 2 ** p_bits)
    if is_prime(p):
        break

# Find a prefix.
#
# prefix * 64**num_b64_suffix_digits + suffix == 0 (mod p)

print(sval)
print(p)
