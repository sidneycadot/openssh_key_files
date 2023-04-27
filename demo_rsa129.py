#! /usr/bin/env -S python3 -B

"""The August 1977 issue of Scientific American featured a 'Mathematical Games' column by Martin Garner
about the RSA cipher, titled "A new kind of cipher that would take millions of years to break".

  See: https://simson.net/ref/1977/Gardner_RSA.pdf

This column proposed the challenge of factoring a 129-digit number in order to break RSA and win 100 US
dollars.

The factorization was announced in 1994 later by 4 prominent number theory researchers, who factored the
number using the Quadratic Sieve algorithm.

Below, we replicate the calculation presented in the column, based on the knowledge of the prime factors of
RSA-129 and the secret message.

"""

import math

from rsa_math import modular_inverse, powermod


def simple_string_to_int(s: str) -> int:
    """Apply the encoding described in the RSA-129 article."""
    result = 0
    for c in s.lower():
        idx = " abcdefghijklmnopqrstuvwxyz".find(c)
        if idx == -1:
            raise ValueError("Unable to encode character {!r}.".format(c))
        result *= 100
        result += idx
    return result


def simple_int_to_string(m: int) -> str:
    """Apply the decoding described in the RSA-129 article."""
    characters = []
    while m != 0:
        characters.append(" abcdefghijklmnopqrstuvwxyz"[m % 100])
        m //= 100
    return "".join(reversed(characters))


def main():
    """Work through the example of the RSA-129 key discussed in Martin Gardner's Scientific American column."""

    print()
    print("=== GENERATING THE PUBLIC/PRIVATE KEY PAIR ===")
    print()

    # The original (secret) pair of prime factors.
    p = 3490529510847650949147849619903898133417764638493387843990820577
    q = 32769132993266709549961988190834461413177642967992942539798288533

    print("Secret primes, selected at random:")
    print()
    print("    p =", p)
    print("    q =", q)
    print()

    # The corresponding public key is (n, e).
    n = p * q  # The product of the two secret primes, given in the article.
    e = 9007   # The public exponent given in the article.

    print("Public key:")
    print()
    print("    n =", n, "(p*q)")
    print("    e =", e, "(chosen public exponent)")
    print()

    # Only the party in possession of 'd' should be able to decode the message.
    #
    # The key property we need: for any M < n, M^(e*d) == M (mod n).
    #
    # Note: the original RSA description prescribes Euler's totient function rather than Carmichael's totient function.
    # Either will work; in fact, ANY multiple of Carmichael's lambda value will work, and Euler's totient is such a multiple.

    carmichael_lambda = math.lcm(p - 1, q - 1)
    euler_phi = (p - 1) * (q - 1)

    print("Calculating the secret exponent d from p, q, and e:")
    print()
    print("    carmichael_lambda(n) =", carmichael_lambda)
    print("    euler_phi(n) =", euler_phi)
    print()

    #d = modular_inverse(e, euler_phi)
    d = modular_inverse(e, carmichael_lambda)

    print("    d =", d)
    print()

    print("=== ENCRYPTION ===")
    print()

    # The secret message.
    plaintext_message_string = "the magic words are squeamish ossifrage"

    plaintext_message_before_encryption = simple_string_to_int(plaintext_message_string)

    print("Plaintext message before encryption:")
    print()
    print("   ", repr(plaintext_message_string))
    print("   ", plaintext_message_before_encryption)
    print()

    # The "ciphertext message" for the RSA-129 challenge is given in the article as a decimal integer.
    ciphertext_message = powermod(plaintext_message_before_encryption, e, n)

    print("Ciphertext message (after encryption using n and e):")
    print()
    print("   ", ciphertext_message)
    print()

    print("=== DECRYPTION ===")
    print()

    plaintext_message_after_decryption = powermod(ciphertext_message, d, n)

    print("Plaintext message (after decryption using n and d):")
    print()
    print("   ", plaintext_message_after_decryption)
    print("   ", repr(simple_int_to_string(plaintext_message_after_decryption)))
    print()

    print("=== SIGNATURE CHECKING ===")
    print()

    # Both this "signature" number and its decrypted version are given in the rticle.

    plaintext_signature_string = "first solver wins one hundred dollars"

    plaintext_signature_before_encryption = simple_string_to_int(plaintext_signature_string)

    print("Plaintext signature before encryption:")
    print()
    print("   ", repr(plaintext_signature_string))
    print("   ", plaintext_signature_before_encryption)
    print()

    ciphertext_signature = powermod(plaintext_signature_before_encryption, d, n)

    # The article gives this 128-digit encrypted signature:
    #
    #   16717861150380844246015271389168\
    #   39824543690103235831121783503844\
    #   69290626554487922371144905095786\
    #   08655662496577974840004057020373

    print("Ciphertext signature (after encryption using n and d):")
    print()
    print("   ", ciphertext_signature)
    print()

    plaintext_signature_after_decryption = powermod(ciphertext_signature, e, n)

    print("Signature (after decryption using n and e):")
    print()
    print("   ", plaintext_signature_after_decryption)
    print("   ", repr(simple_int_to_string(plaintext_signature_after_decryption)))
    print()


if __name__ == "__main__":
    main()
