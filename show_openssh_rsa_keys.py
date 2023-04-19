#! /usr/bin/env -S python3 -B

""" Show the data contained in OpenSSH RSA keys.

Both public and private key files are supported.

The implementation only handles unencrypted private keys (i.e., keys without a passphrase).
"""

import argparse

from openssh_key_types import find_ssh_rsa_keys_in_file, PublicKeyFound, PrivateKeyBlockFound


def count_digits(n: int, base: int) -> int:
    """Count the digits in a number."""
    digits = 0
    while n != 0:
        n //= base
        digits += 1
    return digits


def number_as_string(n: int, verbosity: int):
    """Represent a number as a decimal string."""
    s = str(n)
    if len(s) > 15 and verbosity < 1:
        s = "{:s}xxxxx{:s}".format(s[:5], s[-5:])

    num_decimal_digits = count_digits(n, 10)
    num_binary_digits = count_digits(n, 2)

    suffix = "({} digits, {} bits)".format(num_decimal_digits, num_binary_digits)
    return s + " " + suffix


def report_private_key_block(found: PrivateKeyBlockFound, verbosity: int) -> None:
    """Print report for a private key block."""
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


def report_public_key(found: PublicKeyFound, verbosity: int) -> None:
    """Print report for a public key."""
    print("    public-key (line {:d}):".format(found.line_number))
    print("        e ............ : {:s}".format(number_as_string(found.key.e, verbosity)))
    print("        n ............ : {:s}".format(number_as_string(found.key.n, verbosity)))
    print("        comment ...... : '{:s}'".format(found.key.comment))
    print("    end-of-public-key (line {:d})".format(found.line_number))


def report_ssh_rsa_keys_found(filename: str, keys_found, verbosity: int) -> None:
    """Print report for a public keys and private key blocks found."""
    print("file ('{:s}'):".format(filename))
    for found in keys_found:
        if isinstance(found, PublicKeyFound):
            report_public_key(found, verbosity)
        elif isinstance(found, PrivateKeyBlockFound):
            report_private_key_block(found, verbosity)
    print("end-of-file ('{:s}')".format(filename))


def main():
    """The main function of the tool."""
    parser = argparse.ArgumentParser(description="Show info on OpenSSH RSA keys.")

    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    parser.add_argument("filenames", metavar="filename", nargs="+", help="file to be analyzed")

    args = parser.parse_args()

    for filename in args.filenames:
        with open(filename, "r", encoding='ascii') as fi:
            keys_found = list(find_ssh_rsa_keys_in_file(fi))

        report_ssh_rsa_keys_found(filename, keys_found, int(args.verbose))


if __name__ == "__main__":
    main()
