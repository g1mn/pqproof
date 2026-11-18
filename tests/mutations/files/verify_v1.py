"""Checks release manifests signed before the migration. Read only: it never signs."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def verify_v1(public_v1, manifest, signature):
    try:
        public_v1.verify(signature, manifest, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
