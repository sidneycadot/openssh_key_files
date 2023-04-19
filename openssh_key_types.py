"""Types for representing OpenSSH RSA keys, and corresponding read/write functionality."""

import io
import re
import base64
from typing import NamedTuple, List, Optional, BinaryIO, TextIO


class PublicKey(NamedTuple):
    """The data found in an OpenSSH public RSA-type key."""
    e: int                  # Public exponent. The default value is 0x10001 (65537).
    n: int                  # Modulus; n = p·q.
    comment: Optional[str]  # The commend associated with the key.

    def verify(self) -> None:
        pass


class PrivateKey(NamedTuple):
    #
    # The fields below (up to and including the comment) are encrypted using the passphrase.
    #
    check1: int      # Identical integers check1, check2; these are compared
    check2: int      #   after decryption to check if decryption succeeded. Also, salt values.
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



class PrivateKeyBlock(NamedTuple):
    """The data found in an OpenSSH private RSA-type key.

    In theory, the private key block format allows more than one (public, private) key pair.
    However, this is not used by OpenSSH, and we do not support it.
    """
    ciphername: str            # Name of cipher to be applied. We can only handle "none" at this time.
    kdfname: str               # TODO: what is this?
    kdf: str                   # TODO: what is this?
    public_key: PublicKey
    private_key: PrivateKey    # May be encrypted (if a passphrase is used.)

    def verify(self):
        self.public_key.verify()
        self.private_key.verify()


def octets_to_int(octets: bytes) -> int:
    """Read a big-endian encoded unsigned integer."""
    value = 0
    for octet in octets:
        value = value * 0x100 + octet
    return value


def utf8_octets_to_string(utf8_octets: bytes) -> str:
    return utf8_octets.decode('utf-8')


def read_binary_fixed_size_blob(fi: BinaryIO, size: int) -> bytes:
    return fi.read(size)


def read_binary_fixed_size_integer(fi: BinaryIO, size: int) -> int:
    octets = read_binary_fixed_size_blob(fi, size)
    return octets_to_int(octets)


def read_binary_fixed_size_string(fi: BinaryIO, size: int) -> str:
    utf8_octets = read_binary_fixed_size_blob(fi, size)
    return utf8_octets_to_string(utf8_octets)


def read_binary_variable_size_blob(fi: BinaryIO) -> bytes:
    size = read_binary_fixed_size_integer(fi, 4)
    return read_binary_fixed_size_blob(fi, size)


def read_binary_variable_size_integer(fi: BinaryIO) -> int:
    octets = read_binary_variable_size_blob(fi)
    return octets_to_int(octets)


def read_binary_variable_size_string(fi: BinaryIO) -> str:
    utf8_octets = read_binary_variable_size_blob(fi)
    return utf8_octets_to_string(utf8_octets)


def read_binary_public_key(fi: BinaryIO, comment: Optional[str]) -> PublicKey:

    key_type = read_binary_variable_size_string(fi)
    if key_type != "ssh-rsa":
        raise NotImplementedError("We cannot handle keys of type '{:s}'".format(key_type))

    e = read_binary_variable_size_integer(fi)
    n = read_binary_variable_size_integer(fi)

    return PublicKey(e, n, comment)


def read_binary_private_key(fi: BinaryIO) -> PrivateKey:

    check1 = read_binary_fixed_size_integer(fi, 4)
    check2 = read_binary_fixed_size_integer(fi, 4)

    key_type = read_binary_variable_size_string(fi)
    if key_type != "ssh-rsa":
        raise NotImplementedError("We cannot handle keys of type '{:s}'".format(key_type))

    n       = read_binary_variable_size_integer(fi)
    e       = read_binary_variable_size_integer(fi)
    d       = read_binary_variable_size_integer(fi)
    iqmp    = read_binary_variable_size_integer(fi)
    p       = read_binary_variable_size_integer(fi)
    q       = read_binary_variable_size_integer(fi)
    comment = read_binary_variable_size_string(fi)

    # The remainder are padding bytes.
    padding = fi.read()

    if not all(padding[i] == (i + 1) % 0x100 for i in range(len(padding))):
        raise ValueError("Bad padding bytes.")

    return PrivateKey(check1, check2, n, e, d, iqmp, p, q, comment)


def read_binary_private_key_block(fi: BinaryIO) -> PrivateKeyBlock:

    auth_magic = read_binary_fixed_size_string(fi, 15)
    if auth_magic != "openssh-key-v1\x00":
        raise ValueError("Bad magic bytes at the beginning of the private key collection.")

    ciphername = read_binary_variable_size_string(fi)
    if ciphername != "none":
        raise NotImplementedError("We cannot handle the '{:s}' cipher.".format(ciphername))

    # TODO: understand what these are used for.
    kdfname = read_binary_variable_size_string(fi)
    kdf     = read_binary_variable_size_string(fi)

    number_of_keys = read_binary_fixed_size_integer(fi, 4)
    if number_of_keys != 1:
        raise NotImplementedError("We only support private key blocks with a single public/private key pair.")

    blob = read_binary_variable_size_blob(fi)
    with io.BytesIO(blob) as fi_public_key:
        public_key = read_binary_public_key(fi_public_key, None)

    blob = read_binary_variable_size_blob(fi)
    with io.BytesIO(blob) as fi_private_key:
        private_key = read_binary_private_key(fi_private_key)

    return PrivateKeyBlock(ciphername, kdfname, kdf, public_key, private_key)


class PublicKeyFound(NamedTuple):
    line_number: int
    key: PublicKey


class PrivateKeyBlockFound(NamedTuple):
    first_line_number: int
    last_line_number: int
    bad_lines_skipped: int
    block: PrivateKeyBlock


def find_ssh_rsa_keys_in_file(file_in: TextIO):

    private_key_block_first_line_number = 0  # 0 means: No private key block is currently being processed.
    private_key_block_lines = []

    regexp_private_key_line = re.compile("[A-Za-z0-9+/]+=*")
    regexp_public_key_line  = re.compile("ssh-rsa +([A-Za-z0-9+/]+=*) +(.*)")

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
                        public_key = read_binary_public_key(fi, comment)
                    yield PublicKeyFound(line_number, public_key)
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
                    block = read_binary_private_key_block(fi)
                bad_line_count = line_number - private_key_block_first_line_number - 1 - len(private_key_block_lines)
                yield PrivateKeyBlockFound(private_key_block_first_line_number, line_number, bad_line_count, block)

                # Reset the private key block parsing info.
                private_key_block_first_line_number = 0
                private_key_block_lines.clear()
            else:
                # Parsing a private key block.
                # Verify that the line is well-formatted.
                match = regexp_private_key_line.fullmatch(line)
                if match is not None:
                    private_key_block_lines.append(line)
