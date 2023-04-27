#! /usr/bin/env -S python3 -B

import argparse
import contextlib
from typing import Optional

from rsa_math import factor, calculate_d, calculate_iqmp
from openssh_key_types import find_ssh_rsa_keys_in_file, PublicKeyFound, PrivateKey, PublicKeyList, PrivateKeyList, PrivateKeyBlock, write_private_key_block


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("filename")
    parser.add_argument("--check", type=int, default=0)

    args = parser.parse_args()

    with contextlib.ExitStack() as exit_stack:

        fo = None  # We will only open the output file if needed.
        fi = exit_stack.enter_context(open(args.filename, "r"))

        for found in find_ssh_rsa_keys_in_file(fi):
            if not isinstance(found, PublicKeyFound):
                continue

            public_key = found.key

            n = public_key.n
            e = public_key.e
            comment = public_key.comment

            print("Factoring a {}-digit number ...".format(len(str(n))))
            (p, q) = factor(n)

            d = calculate_d(e, p, q)
            iqmp = calculate_iqmp(p, q)

            private_key = PrivateKey(
                n = n,
                e = e,
                d = d,
                iqmp = iqmp,
                p = p,
                q = q,
                comment = comment
            )

            private_key_list = PrivateKeyList(
                check1 = args.check,
                check2 = args.check,
                keys = [private_key]
            )

            public_key_list = PublicKeyList(
                keys = [public_key]
            )

            private_key_block = PrivateKeyBlock(
                ciphername = 'none',
                kdfname = 'none',
                kdfoptions = b'',
                public_key_list = public_key_list,
                private_key_list = private_key_list
            )

            if fo is None:
                if args.filename.endswith(".pub"):
                    private_key_filename = args.filename[:-4] + ".cracked"
                else:
                    private_key_filename = args.filename + ".cracked"
                fo = exit_stack.enter_context(open(private_key_filename, "w"))

            write_private_key_block(fo, private_key_block)
            print("Wrote private key file '{:s}' ({:d} bytes).".format(private_key_filename, fo.tell()))

        if fo is None:
            print("No OpenSSH keys of type 'ssh-rsa' found.")


if __name__ == "__main__":
    main()
