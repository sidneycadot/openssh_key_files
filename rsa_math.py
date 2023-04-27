"""RSA math."""

import math

from typing import Tuple


def is_prime(n: int) -> bool:
    d = 2
    while d * d <= n:
        if n % d == 0:
            return False
        d += 1
    return True


def next_prime(n: int) -> int:
    while True:
        n += 1
        if is_prime(n):
            return n


def factor(n):
    """TODO: Insert quantum computer right about here."""
    p = 2
    while n % p != 0:
        p = next_prime(p)
    q = n // p
    return (p, q)


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


def modular_inverse(n: int, modulus: int) -> int:
    (nc, modulusc, gcd) = extended_gcd(n, modulus)
    if gcd != 1:
        raise ValueError("The modular inverse does not exist.")
    return nc


def calculate_d(e: int, p: int, q: int):
    carmichael_lambda = math.lcm(p - 1, q - 1)
    d = modular_inverse(e, carmichael_lambda)
    assert (e * d) % carmichael_lambda == 1
    #print("p", p)
    #print("q", q)
    #print("d", d)
    #print("e", e)
    #print("carm", carmichael_lambda)
    return d


def calculate_iqmp(p: int, q: int):
    return modular_inverse(q, p)


def powermod(a: int, b: int, modulus: int):
    """Calculate (a ** b) % modulus, somewhat efficiently."""
    r = 1
    while b != 0:
        if b % 2 != 0:
            r = (r * a) % modulus
        a = (a * a) % modulus
        b //= 2
    return r
