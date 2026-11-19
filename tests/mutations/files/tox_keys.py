# A Python file inside app/.tox, a tox folder in an unusual place (no build file beside it).
from cryptography.hazmat.primitives.asymmetric import rsa

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
