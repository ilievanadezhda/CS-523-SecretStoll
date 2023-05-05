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

class AttributeMap:
    """ A map from attribute names (0, 1 ... L-1) to bytes """
    def __init__(self, L):
        self.L = L
        self.map = {}
        for i in range(L):
            self.map[i] = None

    def get_attribute(self, key):
        return self.map[key]

    def set_attribute(self, key, value):
        if key >= 0 and key < self.L:
            self.map[key] = value
        else:
            raise ValueError("Attribute index out of range")
        
    def get_attributes(self):
        """ Return a list of non-empty attributes """
        return [(key, self.map[key]) for key in self.map if self.map[key] is not None]
    
    def print(self):
        for key in self.map:
            print(key, self.map[key])

class IssueRequest:
    def __init__(self, C, pi):
        self.C = C
        self.pi = pi

class BlindSignature:
    def __init__(self, sigma_1_prime, sigma_2_prime):
        self.sigma_1_prime = sigma_1_prime
        self.sigma_2_prime = sigma_2_prime

def bytes_to_Z_p(m, p):
    """ Convert bytes to Z_p """
    return int.from_bytes(hashlib.sha256(m).digest(), byteorder="big") % p
