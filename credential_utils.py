from typing import Any
import hashlib

class PublicKey:
    """ Public key of the signer/issuer"""
    def __init__(self, g, Y, g_tilde, X_tilde, Y_tilde):
        self.g = g
        self.Y = Y
        self.g_tilde = g_tilde
        self.X_tilde = X_tilde
        self.Y_tilde = Y_tilde
    
class SecretKey:
    """ Secret key of the signer/issuer"""
    def __init__(self, x, X, y):
        self.x = x
        self.X = X
        self.y = y

class Signature:
    """ Signature on a vector of messages"""
    def __init__(self, sigma_1, sigma_2):
        self.sigma_1 = sigma_1
        self.sigma_2 = sigma_2

def bytes_to_Z_p(m, p):
    """ Convert bytes to Z_p """
    return int.from_bytes(hashlib.sha256(m).digest(), byteorder="big") % p
