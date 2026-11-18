"""Signs a release manifest and wraps its data key for the backup host."""
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

WRAP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def new_keys():
    signing = ec.generate_private_key(ec.SECP256R1())
    backup = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return signing, backup


def sign(signing, manifest):
    return signing.sign(manifest, ec.ECDSA(hashes.SHA256()))


def verify(public, manifest, signature):
    try:
        public.verify(signature, manifest, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def wrap_key(backup_public, data_key):
    return backup_public.encrypt(data_key, WRAP)


def unwrap_key(backup, blob):
    return backup.decrypt(blob, WRAP)


if __name__ == "__main__":
    manifest = sys.stdin.buffer.read() if not sys.stdin.isatty() else b"release 1.0\n"
    signing, backup = new_keys()
    sig = sign(signing, manifest)
    data_key = os.urandom(32)
    blob = wrap_key(backup.public_key(), data_key)
    print("signature ok:", verify(signing.public_key(), manifest, sig), "key ok:", unwrap_key(backup, blob) == data_key)
