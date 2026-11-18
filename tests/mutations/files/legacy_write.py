"""Gateway key setup. Every line carries a legacy name or comment, and the key is new."""
from cryptography.hazmat.primitives import hashes  # legacy
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # legacy

legacy_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)  # legacy
legacy_sig = legacy_key.sign(b"manifest", padding.PKCS1v15(), hashes.SHA256())  # legacy
