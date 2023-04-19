#! /usr/bin/env -S python3 -B

""" Show the data contained in OpenSSH RSA keys.

Both public and private key files are supported.

The implementation only handles unencrypted private keys (i.e., keys without a passphrase).
"""

import re
import argparse
import io
import base64
from typing import TextIO, NamedTuple

from openssh_key_types import find_ssh_rsa_keys_in_file, PublicKeyFound, PrivateKeyBlockFound

def count_digits(n: int, base: int) -> int:
    digits = 0
    while n != 0:
        n //= base;
        digits += 1
    return digits


def number_as_string(n: int, verbosity: int):
    s = str(n)
    if len(s) > 15 and verbosity < 1:
        s = "{:s}xxxxx{:s}".format(s[:5], s[-5:])

    num_decimal_digits = count_digits(n, 10)
    num_binary_digits = count_digits(n, 2)

    suffix = "({} digits, {} bits)".format(num_decimal_digits, num_binary_digits)
    return s + " " + suffix


def report_private_key_collection(filename: str, found: PrivateKeyBlockFound, verbosity: int) -> None:
    print("    private-key-block (lines {:d}-{:d}):".format(found.first_line_number, found.last_line_number))
    print("        cipher ........... : '{:s}'".format(found.block.ciphername))
    print("        kdfname .......... : '{:s}'".format(found.block.kdfname))
    print("        kdf .............. : '{:s}'".format(found.block.kdf))
    print("        public-key:")
    print("            e ............ : {:s}".format(number_as_string(found.block.public_key.e, verbosity)))
    print("            n ............ : {:s}".format(number_as_string(found.block.public_key.n, verbosity)))
    print("        end-of-public-key")
    print("        private-key:")
    print("            check1 ....... : 0x{:08x}".format(found.block.private_key.check1))
    print("            check2 ....... : 0x{:08x}".format(found.block.private_key.check1))
    print("            n ............ : {:s}".format(number_as_string(found.block.private_key.n, verbosity)))
    print("            e ............ : {:s}".format(number_as_string(found.block.private_key.e, verbosity)))
    print("            d ............ : {:s}".format(number_as_string(found.block.private_key.d, verbosity)))
    print("            iqmp ......... : {:s}".format(number_as_string(found.block.private_key.iqmp, verbosity)))
    print("            p ............ : {:s}".format(number_as_string(found.block.private_key.p, verbosity)))
    print("            q ............ : {:s}".format(number_as_string(found.block.private_key.q, verbosity)))
    print("            comment ...... : '{:s}'".format(found.block.private_key.comment))
    print("        end-of-private-key")
    print("    end-of-private-key-block (lines {:d}-{:d})".format(found.first_line_number, found.last_line_number))


def report_public_key(filename: str, key_found: PublicKeyFound, verbosity: int) -> None:
    print("    public-key (line {:d}):".format(key_found.line_number))
    print("        e ............ : {:s}".format(number_as_string(key_found.key.e, verbosity)))
    print("        n ............ : {:s}".format(number_as_string(key_found.key.n, verbosity)))
    print("        comment ...... : '{:s}'".format(key_found.key.comment))
    print("    end-of-public-key (line {:d})".format(key_found.line_number))


def report_ssh_rsa_keys_found(filename: str, keys_found, verbosity: int) -> None:

    print("file ('{:s}'):".format(filename))
    for key_found in keys_found:
        if isinstance(key_found, PublicKeyFound):
            report_public_key(filename, key_found, verbosity)
        elif isinstance(key_found, PrivateKeyBlockFound):
            report_private_key_collection(filename, key_found, verbosity)
    print("end-of-file ('{:s}')".format(filename))



def main():

    parser = argparse.ArgumentParser(description="Show info on OpenSSH RSA keys.")

    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    parser.add_argument("filenames", metavar="filename", nargs="+", help="file to be analyzed")

    args = parser.parse_args()

    for filename in args.filenames:
        with open(filename, "r") as fi:
            keys_found = list(find_ssh_rsa_keys_in_file(fi))

    report_ssh_rsa_keys_found(filename, keys_found, int(args.verbose))


if __name__ == "__main__":
    main()
