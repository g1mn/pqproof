"""Reads records signed before the migration. Read only: no new key, signature or encryption."""
from cryptography.hazmat.primitives import serialization


def load_legacy_rsa_public(blob):
    legacy_rsa_pub = serialization.load_pem_public_key(blob)
    return legacy_rsa_pub
