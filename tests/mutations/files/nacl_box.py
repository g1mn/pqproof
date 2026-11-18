from nacl.public import PrivateKey, Box


def new_box(peer):
    sk = PrivateKey.generate()
    return Box(sk, peer)
