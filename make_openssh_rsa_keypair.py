#! /usr/bin/env -S python3 -B

"""Given values p and q, write the corresponding private and public RSA key files in OpenSSH format."""

import argparse

from rsa_math import calculate_d, calculate_iqmp
from openssh_key_types import PublicKey, PrivateKey, PublicKeyList, PrivateKeyList, PrivateKeyBlock, write_public_key, write_private_key_block


def main():
    """Main function."""

    parser = argparse.ArgumentParser(description="Make SSH keypair (private and public keys).")

    parser.add_argument("-c", "--comment", default='', help="comment associated with the key (default: '')")

    parser.add_argument("--check", default=0, type=int, help="check value used to verify keyphrase integrity (default: 0)")
    parser.add_argument("-e", default=0x10001, type=int, help="public exponent e (default: 65537)")
    parser.add_argument("p", type=int, help='prime factor p')
    parser.add_argument("q", type=int, help='prime factor q')
    parser.add_argument("filename", help="private key filename. The public key will have the same name with '.pub' appended.")

    args = parser.parse_args()

    # Extract argument values and calculate the missing pieces.

    e = args.e
    p = args.p
    q = args.q

    n = p * q

    d = calculate_d(p, q, e)
    iqmp = calculate_iqmp(p, q)

    # ----- Construct OpenSSH 'ssh-rsa'-type keys.

    public_key = PublicKey(
        e = e,
        n = n,
        comment = args.comment
    )

    private_key = PrivateKey(
        n = n,
        e = e,
        d = d,
        iqmp = iqmp,
        p = p,
        q = q,
        comment = args.comment
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

    # Write the private and public key files.

    private_key_filename = args.filename

    with open(private_key_filename, "w", encoding="utf-8") as fo:
        write_private_key_block(fo, private_key_block)
        print("Wrote private key file '{:s}' ({:d} bytes).".format(private_key_filename, fo.tell()))

    public_key_filename = args.filename + ".pub"

    with open(public_key_filename, "w", encoding="utf-8") as fo:
        write_public_key(fo, public_key)
        print("Wrote public key file '{:s}' ({:d} bytes).".format(public_key_filename, fo.tell()))


if __name__ == "__main__":
    main()
