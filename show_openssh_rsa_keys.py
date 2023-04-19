#! /usr/bin/env python3

""" Show the data contained in OpenSSH RSA keys.

Both public and private key files are supported.

The implementation only handles unencrypted private keys (i.e., keys without a passphrase).
"""

import re
import argparse
import io
import base64
from typing import NamedTuple, BinaryIO, List, Optional


class PublicKeyData(NamedTuple):
    """The data found in an OpenSSH public RSA-type key."""
    e: int        # Public exponent. The default value is 0x10001 (65537).
    n: int        # Modulus; n = p·q.
    comment: Optional[str]

    def verify(self) -> None:
        pass


class PrivateKeyData(NamedTuple):
    #
    # The fields below (up to and including the comment) are encrypted using the passphrase.
    #
    check1: int      # Identical integers check1, check2; these are compared
    check2: int      # after decryption to assess if decryption succeeded. Also, salt values.
    #
    n: int           # Modulus; n = p·q.
    e: int           # Public exponent. The default value is 0x10001 (65537).
    d: int           # Secret exponent. Derived from (n, e); (e·d) ≡ 1 (mod λ(n)).
    iqmp: int        # Modular inverse of q (mod p): q·iqmp ≡ 1 (mod p).
    p: int           # First prime factor (secret).
    q: int           # Second prime factor (secret).
    #
    comment: str     # A comment that goes along with the key.
    #
    # Note: in the binary format, padding bytes may follow.

    def verify(self) -> None:
        """Verify consistency of private key."""

        ok = (self.check1 == self.check2)
        if not ok:
            raise ValueError("Bad check values.")

        ok = (self.n == self.p * self.q)
        if not ok:
            raise ValueError("RSA check failed: (n = p·q).")

        carmichael_lambda = (self.p - 1) * (self.q - 1)

        ok = (self.e * self.d % carmichael_lambda == 1)
        if not ok:
            raise ValueError("RSA check failed: d·e ≡ 1 (mod λ(n)).")

        ok = (self.q * self.iqmp % self.p == 1)
        if not ok:
            raise ValueError("RSA check failed: q·iqmp ≡ 1 (mod p).")


class PublicPrivateKeyPair(NamedTuple):

    public: PublicKeyData
    private: PrivateKeyData

    def verify(self) -> None:
        self.public.verify()
        self.private.verify()
        # Check consistency.
        ok = (self.public.n == self.private.n) and (self.public.e == self.private.e)
        if not ok:
            raise ValueError("Mismatch between public and private key values.")


class PrivateKeyCollection(NamedTuple):
    """The data found in an OpenSSH private RSA-type key."""
    ciphername: str  # Name of cipher to be applied. We can only handle "none" at this time.
    kdfname: str     # TODO: what is this?
    kdf: str         # TODO: what is this?
    keypairs: List[PublicPrivateKeyPair]

    def verify(self):
        for keypair in self.keypairs:
            keypair.verify()


def octets_to_int(octets: bytes) -> int:
    """We assume that the number is unsigned."""
    value = 0
    for octet in octets:
        value = value * 0x100 + octet
    return value


def blob_to_string(blob: bytes) -> str:
    return blob.decode('utf-8')


def read_fixed_size_blob(fi: BinaryIO, size: int) -> bytes:
    return fi.read(size)


def read_fixed_size_integer(fi: BinaryIO, size: int) -> int:
    octets = read_fixed_size_blob(fi, size)
    return octets_to_int(octets)


def read_fixed_size_string(fi: BinaryIO, size: int) -> str:
    blob = read_fixed_size_blob(fi, size)
    return blob_to_string(blob)


def read_variable_size_blob(fi: BinaryIO) -> bytes:
    size = read_fixed_size_integer(fi, 4)
    return read_fixed_size_blob(fi, size)


def read_variable_size_integer(fi: BinaryIO) -> int:
    octets = read_variable_size_blob(fi)
    return octets_to_int(octets)


def read_variable_size_string(fi: BinaryIO) -> str:
    blob = read_variable_size_blob(fi)
    return blob_to_string(blob)


def read_public_key(fi: BinaryIO, comment: Optional[str]) -> PublicKeyData:

    key_type = read_variable_size_string(fi)
    if key_type != "ssh-rsa":
        raise NotImplementedError()

    e = read_variable_size_integer(fi)
    n = read_variable_size_integer(fi)

    return PublicKeyData(e, n, comment)


def read_private_key(fi: BinaryIO) -> PrivateKeyData:

    check1 = read_fixed_size_integer(fi, 4)
    check2 = read_fixed_size_integer(fi, 4)

    key_type = read_variable_size_string(fi)
    if key_type != "ssh-rsa":
        raise NotImplementedError()

    n = read_variable_size_integer(fi)
    e = read_variable_size_integer(fi)
    d = read_variable_size_integer(fi)
    iqmp = read_variable_size_integer(fi)
    p = read_variable_size_integer(fi)
    q = read_variable_size_integer(fi)
    comment = read_variable_size_string(fi)

    # Rhe remainder should be padding bytes.
    padding = fi.read()

    if not all(padding[i] == (i + 1) % 0x100 for i in range(len(padding))):
        raise ValueError("Bad padding bytes.")

    return PrivateKeyData(check1, check2, n, e, d, iqmp, p, q, comment)


def read_private_key_collection(fi: BinaryIO) -> PrivateKeyCollection:

    auth_magic = read_fixed_size_string(fi, 15)
    if auth_magic != "openssh-key-v1\x00":
        raise ValueError()

    ciphername = read_variable_size_string(fi)
    if ciphername != "none":
        raise NotImplementedError()

    # TODO: understand what these are used for.
    kdfname = read_variable_size_string(fi)
    kdf = read_variable_size_string(fi)

    number_of_keys = read_fixed_size_integer(fi, 4)

    keypairs = []

    while number_of_keys != 0:

        blob = read_variable_size_blob(fi)
        with io.BytesIO(blob) as fi_public_key:
            public_key = read_public_key(fi_public_key, None)

        blob = read_variable_size_blob(fi)
        with io.BytesIO(blob) as fi_private_key:
            private_key_envelope = read_private_key(fi_private_key)

        keypair = PublicPrivateKeyPair(public_key, private_key_envelope)
        keypairs.append(keypair)

        number_of_keys -= 1

    collection = PrivateKeyCollection(ciphername, kdfname, kdf, keypairs)

    return collection


def read_private_key_file(filename: str) -> PrivateKeyCollection:
    """
    """
    key_lines = None
    with open(filename, "r") as fi:
        for line in fi:
            line = line.strip()
            if line == '-----BEGIN OPENSSH PRIVATE KEY-----':
                assert key_lines is None
                key_lines = []
            elif line == '-----END OPENSSH PRIVATE KEY-----':
                assert key_lines is not None
            elif key_lines is not None:
                key_lines.append(line)

    assert key_lines is not None

    blob = base64.b64decode("".join(key_lines))

    with io.BytesIO(blob) as fi:
        return read_private_key_collection(fi)


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


def print_private_key_collection_report(filename: str, first_line_number: int, last_line_number: int, bad_line_count: int,
                                        collection: PrivateKeyCollection, verbosity: int) -> None:
    print("    private-key-block (lines {:d}-{:d}):".format(first_line_number, last_line_number))
    print("        cipher ....... : '{:s}'".format(collection.ciphername))
    print("        kdfname ...... : '{:s}'".format(collection.kdfname))
    print("        kdf .......... : '{:s}'".format(collection.kdf))
    for (keypair_index, keypair) in enumerate(collection.keypairs, 1):
        print("        private-public-keypair ({:d} of {:d}):".format(keypair_index, len(collection.keypairs)))
        print("            public-key:")
        print("                e ............ : {:s}".format(number_as_string(keypair.public.e, verbosity)))
        print("                n ............ : {:s}".format(number_as_string(keypair.public.n, verbosity)))
        print("            end-of-public-key")
        print("            private-key:")
        print("                check1 ....... : 0x{:08x}".format(keypair.private.check1))
        print("                check2 ....... : 0x{:08x}".format(keypair.private.check1))
        print("                n ............ : {:s}".format(number_as_string(keypair.private.n, verbosity)))
        print("                e ............ : {:s}".format(number_as_string(keypair.private.e, verbosity)))
        print("                d ............ : {:s}".format(number_as_string(keypair.private.d, verbosity)))
        print("                iqmp ......... : {:s}".format(number_as_string(keypair.private.iqmp, verbosity)))
        print("                p ............ : {:s}".format(number_as_string(keypair.private.p, verbosity)))
        print("                q ............ : {:s}".format(number_as_string(keypair.private.q, verbosity)))
        print("                comment ...... : '{:s}'".format(keypair.private.comment))
        print("            end-of-private-key")
        print("        end-of-private-public-keypair ({:d} of {:d})".format(keypair_index, len(collection.keypairs)))
    print("    end-of-private-key-block (lines {:d}-{:d})".format(first_line_number, last_line_number))


def print_public_key_report(filename: str, line_number: int, key: PublicKeyData, verbosity: int) -> None:
    print("    public-key (line {:d}):".format(line_number))
    print("        e ............ : {:s}".format(number_as_string(key.e, verbosity)))
    print("        n ............ : {:s}".format(number_as_string(key.n, verbosity)))
    print("        comment ...... : '{:s}'".format(key.comment))
    print("    end-of-public-key (line {:d})".format(line_number))


def process_file(filename: str, verbosity: int) -> None:

    private_key_block_first_line_number = 0  # 0 means: No block currently being processed.
    private_key_block_lines = []

    regexp_private_key_line = re.compile("[A-Za-z0-9+/]+=*")
    regexp_public_key_line  = re.compile("ssh-rsa +([A-Za-z0-9+/]+=*) +(.*)")

    with open(filename, "r") as file_in:
        print("file ('{:s}'):".format(filename))
        for (line_number, line) in enumerate(file_in, 1):
            line = line.strip()
            if private_key_block_first_line_number == 0:
                # We're not currently parsing a private key.
                if line == "-----BEGIN OPENSSH PRIVATE KEY-----":
                    # A private key is starting.
                    private_key_block_first_line_number = line_number
                else:
                    # Check if it could be a single-line public key.
                    match = regexp_public_key_line.match(line)
                    if match is not None:
                        public_key_base64_string = match.group(1)
                        comment = match.group(2)
                        blob = base64.b64decode(public_key_base64_string)
                        with io.BytesIO(blob) as fi:
                            public_key = read_public_key(fi, comment)
                        print_public_key_report(filename, line_number, public_key, verbosity)
                    else:
                        # It is just a random line; ignore it.
                        pass
            else:
                # We're currently parsing a private key block.
                if line == "-----END OPENSSH PRIVATE KEY-----":
                    # Found the end of the private key.

                    private_key_base64_string = "".join(private_key_block_lines)

                    blob = base64.b64decode(private_key_base64_string)

                    with io.BytesIO(blob) as fi:
                        collection = read_private_key_collection(fi)
                    bad_line_count = line_number - private_key_block_first_line_number - 1 - len(private_key_block_lines)
                    print_private_key_collection_report(filename, private_key_block_first_line_number, line_number, bad_line_count, collection, verbosity)
                        
                    # Reset the private key block parsing info.
                    private_key_block_first_line_number = 0
                    private_key_block_lines.clear()
                else:
                    # Parsing a private key block.
                    # Verify that the line is well-formatted.
                    match = regexp_private_key_line.fullmatch(line)
                    if match is not None:
                        private_key_block_lines.append(line)
        print("end-of-file ('{:s}')".format(filename))

def main():

    parser = argparse.ArgumentParser(description="Show info on OpenSSH RSA keys.")

    parser.add_argument("filenames", metavar="filename", nargs="+", help="file to be analyzed")

    args = parser.parse_args()

    for filename in args.filenames:
        process_file(filename, 0)


if __name__ == "__main__":
    main()
