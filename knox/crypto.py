import binascii
from os import urandom as generate_bytes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.hashes import SHA512


def create_token_string():
    return binascii.hexlify(
        generate_bytes(int(64 / 2))
    ).decode()


def hash_token(token):
    digest = hashes.Hash(SHA512(), backend=default_backend())
    digest.update(binascii.unhexlify(token))
    return binascii.hexlify(digest.finalize()).decode()
