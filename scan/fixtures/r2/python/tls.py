ctx.options |= ssl.OP_NO_TLSv1_3
from nacl.signing import SigningKey
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
