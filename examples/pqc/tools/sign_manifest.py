"""Signs a release manifest and wraps its data key for the backup host."""
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CAPSULE = 1088  # ML-KEM-768 ciphertext bytes
NONCE = 12


def new_keys():
    signing = mldsa.MLDSA65PrivateKey.generate()
    backup = mlkem.MLKEM768PrivateKey.generate()
    return signing, backup


def sign(signing, manifest):
    return signing.sign(manifest)


def verify(public, manifest, signature):
    try:
        public.verify(signature, manifest)
        return True
    except InvalidSignature:
        return False


def wrap_key(backup_public, data_key):
    shared, capsule = backup_public.encapsulate()
    nonce = os.urandom(NONCE)
    return capsule + nonce + AESGCM(shared).encrypt(nonce, data_key, None)


def unwrap_key(backup, blob):
    capsule, nonce, body = blob[:CAPSULE], blob[CAPSULE:CAPSULE + NONCE], blob[CAPSULE + NONCE:]
    shared = backup.decapsulate(capsule)
    return AESGCM(shared).decrypt(nonce, body, None)


if __name__ == "__main__":
    manifest = sys.stdin.buffer.read() if not sys.stdin.isatty() else b"release 1.0\n"
    signing, backup = new_keys()
    sig = sign(signing, manifest)
    data_key = os.urandom(32)
    blob = wrap_key(backup.public_key(), data_key)
    print("signature ok:", verify(signing.public_key(), manifest, sig), "key ok:", unwrap_key(backup, blob) == data_key)
