"""Types for representing OpenSSH RSA keys and functions to read and write them.

References:
- https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
- https://dnaeon.github.io/openssh-private-key-binary-format/
"""

import math
import io
import re
import base64
from typing import List, NamedTuple, Optional, BinaryIO, TextIO


class PublicKey(NamedTuple):
    """The data found in an OpenSSH public RSA-type key."""
    e: int                  # Public exponent. The default value is 0x10001 (65537).
    n: int                  # Modulus; n = p·q.
    comment: Optional[str]  # The comment associated with the key.

    def verify(self) -> None:
        """Verify the consistency of the public key."""
        return

class PublicKeyList(NamedTuple):
    """A list of public keys."""
    keys: List[PublicKey]

    def verify(self) -> None:
        """Verify the consistency of the public keys."""
        for key in self.keys:
            key.verify()


class PrivateKey(NamedTuple):
    """The data in an OpenSSH private RSA-type key."""
    n: int           # Modulus; n = p·q.
    e: int           # Public exponent. The default value is 0x10001 (65537).
    d: int           # Secret exponent. Derived from (n, e); (e·d) ≡ 1 (mod λ(n)).
    iqmp: int        # Modular inverse of q (mod p): q·iqmp ≡ 1 (mod p).
    p: int           # First prime factor (secret).
    q: int           # Second prime factor (secret).
    comment: str     # A comment that goes along with the key.

    def verify(self) -> None:
        """Verify the consistency of the private key."""

        ok = (self.n == self.p * self.q)
        if not ok:
            raise ValueError("RSA check failed: (n = p·q).")

        carmichael_lambda = math.lcm(self.p - 1, self.q - 1)

        ok = (self.e * self.d) % carmichael_lambda == 1
        if not ok:
            raise ValueError("RSA check failed: d·e ≡ 1 (mod λ(n)).")

        ok = (self.q * self.iqmp % self.p == 1)
        if not ok:
            raise ValueError("RSA check failed: q·iqmp ≡ 1 (mod p).")


class PrivateKeyList(NamedTuple):
    """The data in an OpenSSH private RS-type key."""
    #
    # The fields below (up to and including the comment) are encrypted using the passphrase.
    #
    check1: int  # Identical integers check1, check2; these are compared
    check2: int  # after decryption to check if decryption succeeded. Also, salt values.
    #
    keys: List[PrivateKey]
    #
    # In the binary format, padding bytes may follow to make sure the size of the
    # encrypted private key list is a multiple of the cipher's block size.

    def verify(self) -> None:
        """Verify the consistency of the private key list."""

        ok = (self.check1 == self.check2)
        if not ok:
            raise ValueError("Bad check values.")

        for key in self.keys:
            key.verify()


class PrivateKeyBlock(NamedTuple):
    """The data found in an OpenSSH private RSA-type key.

    In theory, the private key block format allows more than one (public, private) key pair.
    However, this is not used by OpenSSH, and we do not support it.
    """
    ciphername: str            # Name of cipher to be applied. We can only handle "none" at this time.
    kdfname: str               # KDF (Key Derivation Function) name: "none" or "bcrypt".
    kdfoptions: bytes

    public_key_list: PublicKeyList    # Not encrypted.
    private_key_list: PrivateKeyList  # May be encrypted (if a passphrase is used.)

    def verify(self):
        """Verify consistency of the data in the private key block."""
        self.public_key_list.verify()
        self.private_key_list.verify()


def octets_to_int(octets: bytes) -> int:
    """Convert bytes to an unsigned integer."""
    value = 0
    for octet in octets:
        value = value * 0x100 + octet
    return value


def int_to_octets(n: int) -> bytes:
    """Convert an unsigned integer to bytes."""
    octets = []
    while n != 0:
        octets.append(n % 0x100)
        n //= 0x100

    # The sign bit of the most-significant byte should be 0.
    # If not, we will add an extra zero byte.
    if len(octets) != 0 and octets[-1] >= 0x80:
        octets.append(0x00)
    return bytes(reversed(octets))


def utf8_octets_to_string(utf8_octets: bytes) -> str:
    """Convert bytes to a string."""
    return utf8_octets.decode('utf-8')


def string_to_utf8_octets(s: str) -> bytes:
    """Convert string to bytes."""
    return s.encode('utf-8')


def read_binary_fixed_size_blob(fi: BinaryIO, size: int) -> bytes:
    """Read a fixed-size binary blob."""
    return fi.read(size)


def write_binary_fixed_size_blob(fo: BinaryIO, blob: bytes) -> None:
    """Write a fixed-size binary blob."""
    fo.write(blob)


def read_binary_fixed_size_integer(fi: BinaryIO, size: int) -> int:
    """Read a fixed-size integer."""
    octets = read_binary_fixed_size_blob(fi, size)
    return octets_to_int(octets)


def write_binary_fixed_size_integer(fo: BinaryIO, n: int, size: int) -> None:
    """Write a fixed-size integer."""
    octets = []
    while len(octets) < size:
        octets.append(n % 0x100)
        n //= 0x100
    if n != 0:
        raise RuntimeError("Integer value does not fit.")
    blob = bytes(reversed(octets))
    write_binary_fixed_size_blob(fo, blob)


def read_binary_fixed_size_string(fi: BinaryIO, size: int) -> str:
    """Read a fixed-size string."""
    utf8_octets = read_binary_fixed_size_blob(fi, size)
    return utf8_octets_to_string(utf8_octets)


def write_binary_fixed_size_string(fo: BinaryIO, s: str) -> None:
    """Write a fixed-size string."""
    utf8_octets = string_to_utf8_octets(s)
    write_binary_fixed_size_blob(fo, utf8_octets)


def read_binary_variable_size_blob(fi: BinaryIO) -> bytes:
    """Read a variable-size binary blob."""
    size = read_binary_fixed_size_integer(fi, 4)
    return read_binary_fixed_size_blob(fi, size)


def write_binary_variable_size_blob(fo: BinaryIO, blob: bytes) -> None:
    """Write a variable-size binary blob."""
    size = len(blob)
    write_binary_fixed_size_integer(fo, size, 4)
    write_binary_fixed_size_blob(fo, blob)


def read_binary_variable_size_integer(fi: BinaryIO) -> int:
    """Read a variable-size integer."""
    octets = read_binary_variable_size_blob(fi)
    return octets_to_int(octets)


def write_binary_variable_size_integer(fo: BinaryIO, n: int) -> None:
    """Write a variable-size integer."""
    octets = int_to_octets(n)
    write_binary_variable_size_blob(fo, octets)


def read_binary_variable_size_string(fi: BinaryIO) -> str:
    """Read a variable-size string."""
    utf8_octets = read_binary_variable_size_blob(fi)
    return utf8_octets_to_string(utf8_octets)


def write_binary_variable_size_string(fo: BinaryIO, s: str) -> None:
    """Write a variable-size string."""
    utf8_octets = string_to_utf8_octets(s)
    write_binary_variable_size_blob(fo, utf8_octets)


def read_binary_public_key(fi: BinaryIO, comment: Optional[str]) -> PublicKey:
    """Read a public key."""
    key_type = read_binary_variable_size_string(fi)
    if key_type != "ssh-rsa":
        raise NotImplementedError("We cannot handle keys of type '{:s}'".format(key_type))

    e = read_binary_variable_size_integer(fi)
    n = read_binary_variable_size_integer(fi)

    return PublicKey(e, n, comment)


def write_binary_public_key(fo: BinaryIO, key: PublicKey) -> None:
    """Write binary public key."""
    write_binary_variable_size_string(fo, "ssh-rsa")
    write_binary_variable_size_integer(fo, key.e)
    write_binary_variable_size_integer(fo, key.n)


def read_binary_public_key_list(fi: BinaryIO, number_of_keys: int) -> PublicKeyList:
    """Read a public key list."""

    keys = [read_binary_public_key(fi, None) for i in range(number_of_keys)]

    remaining_bytes = fi.read()
    if len(remaining_bytes) != 0:
        raise RuntimeError("Unexpected bytes at the end.")

    return PublicKeyList(keys)


def write_binary_public_key_list(fo: BinaryIO, public_key_list: PublicKeyList) -> None:
    """Write a public key list."""

    for key in public_key_list.keys:
        write_binary_public_key(fo, key)


def read_binary_private_key(fi: BinaryIO) -> PrivateKey:
    """Read a private key."""

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

    return PrivateKey(n, e, d, iqmp, p, q, comment)


def write_binary_private_key(fo: BinaryIO, key: PrivateKey) -> None:
    """Write a private key."""

    write_binary_variable_size_string(fo, "ssh-rsa")
    write_binary_variable_size_integer(fo, key.n)
    write_binary_variable_size_integer(fo, key.e)
    write_binary_variable_size_integer(fo, key.d)
    write_binary_variable_size_integer(fo, key.iqmp)
    write_binary_variable_size_integer(fo, key.p)
    write_binary_variable_size_integer(fo, key.q)
    write_binary_variable_size_string(fo, key.comment)


def read_binary_private_key_list(fi: BinaryIO, number_of_keys: int) -> PrivateKeyList:
    """Read a private key list."""

    offset_1 = fi.tell()

    check1 = read_binary_fixed_size_integer(fi, 4)
    check2 = read_binary_fixed_size_integer(fi, 4)

    keys = [read_binary_private_key(fi) for i in range(number_of_keys)]

    offset_2 = fi.tell()

    block_size = 8  # For "none" cipher.
    padding_size = -(offset_2 - offset_1) % block_size

    padding = read_binary_fixed_size_blob(fi, padding_size)

    if not all(padding[i] == (i + 1) % 0x100 for i in range(len(padding))):
        raise ValueError("Bad padding bytes.")

    remaining_bytes = fi.read()
    if len(remaining_bytes) != 0:
        raise RuntimeError("Unexpected bytes at the end.")

    return PrivateKeyList(check1, check2, keys)


def write_binary_private_key_list(fo: BinaryIO, private_key_list: PrivateKeyList) -> None:
    """Write a private key list."""

    offset_1 = fo.tell()

    write_binary_fixed_size_integer(fo, private_key_list.check1, 4)
    write_binary_fixed_size_integer(fo, private_key_list.check2, 4)

    for key in private_key_list.keys:
        write_binary_private_key(fo, key)

    offset_2 = fo.tell()

    block_size = 8  # For "none" cipher.
    padding_size = -(offset_2 - offset_1) % block_size

    padding = bytes((i + 1) % 0x100 for i in range(padding_size))

    write_binary_fixed_size_blob(fo, padding)


def read_binary_private_key_block(fi: BinaryIO) -> PrivateKeyBlock:
    """Read a private key block."""

    auth_magic = read_binary_fixed_size_string(fi, 15)
    if auth_magic != "openssh-key-v1\x00":
        raise ValueError("Bad magic bytes at the beginning of the private key collection.")

    ciphername = read_binary_variable_size_string(fi)
    if ciphername != "none":
        raise NotImplementedError("We cannot handle the '{:s}' cipher.".format(ciphername))

    kdfname = read_binary_variable_size_string(fi)
    kdfoptions = read_binary_variable_size_blob(fi)

    number_of_keys = read_binary_fixed_size_integer(fi, 4)

    public_keys_blob = read_binary_variable_size_blob(fi)
    with io.BytesIO(public_keys_blob) as fi_public_keys:
        public_keys = read_binary_public_key_list(fi_public_keys, number_of_keys)

    private_keys_blob = read_binary_variable_size_blob(fi)
    with io.BytesIO(private_keys_blob) as fi_private_keys:
        private_keys = read_binary_private_key_list(fi_private_keys, number_of_keys)

    return PrivateKeyBlock(ciphername, kdfname, kdfoptions, public_keys, private_keys)


def write_binary_private_key_block(fo: BinaryIO, block: PrivateKeyBlock) -> None:
    """Write a private key block."""

    if len(block.public_key_list.keys) != len(block.private_key_list.keys):
        raise RuntimeError()

    number_of_keys = len(block.public_key_list)

    write_binary_fixed_size_string(fo, "openssh-key-v1\x00")
    write_binary_variable_size_string(fo, block.ciphername)
    write_binary_variable_size_string(fo, block.kdfname)
    write_binary_variable_size_blob(fo, block.kdfoptions)
    write_binary_fixed_size_integer(fo, number_of_keys, 4)

    with io.BytesIO() as f_public_key_envelope:
        write_binary_public_key_list(f_public_key_envelope, block.public_key_list)
        public_key_envelope = f_public_key_envelope.getvalue()
    write_binary_variable_size_blob(fo, public_key_envelope)

    with io.BytesIO() as f_private_key_envelope:
        write_binary_private_key_list(f_private_key_envelope, block.private_key_list)
        private_key_envelope = f_private_key_envelope.getvalue()
    write_binary_variable_size_blob(fo, private_key_envelope)


class PublicKeyFound(NamedTuple):
    """A public key that was found in a text stream."""
    line_number: int
    key: PublicKey


class PrivateKeyBlockFound(NamedTuple):
    """A private key block that was found in a text stream."""
    first_line_number: int
    last_line_number: int
    bad_lines_skipped: int
    block: PrivateKeyBlock


def find_ssh_rsa_keys_in_file(file_in: TextIO):
    """Find public keys and private key blocks in a given text stream."""
    # pylint: disable=too-many-locals
    private_key_block_first_line_number = 0  # 0 means: No private key block is currently being processed.
    private_key_block_lines = []

    regexp_private_key_line = re.compile("[A-Za-z0-9+/]+=*")
    regexp_public_key_line  = re.compile("ssh-rsa +([A-Za-z0-9+/]+=*) *(.*)")

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


def write_private_key_block(fo: TextIO, block: PrivateKeyBlock) -> None:
    """Write a private key block."""
    with io.BytesIO() as fo_binary:
        write_binary_private_key_block(fo_binary, block)
        binary_private_key_block = fo_binary.getvalue()

    base64_encoded_private_key_block = base64.b64encode(binary_private_key_block).decode('ascii')

    print("-----BEGIN OPENSSH PRIVATE KEY-----", file=fo)

    max_line_size = 70
    offset = 0
    while offset < len(base64_encoded_private_key_block):
        print(base64_encoded_private_key_block[offset:offset + max_line_size], file=fo)
        offset += max_line_size

    print("-----END OPENSSH PRIVATE KEY-----", file=fo)


def write_public_key(fo: TextIO, key: PublicKey, end: str='\n') -> None:
    """Read a private key block."""
    with io.BytesIO() as fo_binary:
        write_binary_public_key(fo_binary, key)
        binary_public_key = fo_binary.getvalue()

    base64_encoded_public_key = base64.b64encode(binary_public_key).decode('ascii')

    if len(key.comment) == 0:
        print("ssh-rsa {:s}".format(base64_encoded_public_key), file=fo, end=end)
    else:
        print("ssh-rsa {:s} {:s}".format(base64_encoded_public_key, key.comment), file=fo, end=end)
