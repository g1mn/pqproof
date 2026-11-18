import hashlib
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519, padding
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES, DES, ARC4

priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ec_priv = ec.generate_private_key(ec.SECP384R1())
eph = x25519.X25519PrivateKey.generate()
ct = priv.public_key().encrypt(b"k", padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
digest = hashlib.sha1(b"data").hexdigest()
token = jwt.encode({"sub": "u1"}, priv, algorithm="RS256")
claims = jwt.decode(token, ec_priv.public_key(), algorithms=["ES256"])
legacy = AES.new(b"0" * 16, AES.MODE_ECB)
old = DES.new(b"8bytekey", DES.MODE_CBC)
ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH); ctx.set_ecdh_curve("prime256v1")
ctx.set_ecdh_curve(curve_name)
