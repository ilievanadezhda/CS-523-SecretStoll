import hashlib
from typing import List

from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1


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
        if 0 <= key < self.L:
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
    # return int.from_bytes(hashlib.sha256(m).digest(), byteorder="big") % p
    # todo: check
    return Bn.from_binary(hashlib.sha256(m).digest()).int() % p


def G1_no_identity():
    element = G1.generator()
    while element == G1.unity:
        element = G1.generator()
    return element


def pedersen_commitment(secrets: List[int]):
    p = G1.order()
    l = len(secrets)

    generators = [G1.generator() for _ in secrets]
    randoms = [G1.order().random() for _ in secrets]

    com = generators[0] ** secrets[0]
    R = generators[0] ** randoms[0]
    for gen_i in range(1, l):
        com *= generators[gen_i] ** secrets[gen_i]
        R *= generators[gen_i] ** randoms[gen_i]

    challenge = hashlib.sha256()
    for generator in generators:
        challenge.update(generator.to_binary())
    challenge.update(R.to_binary())

    c = Bn.from_binary(challenge.digest()).int()

    responses = [(randoms[i] - c * secrets[i]) % p for i in range(l)]

    return generators, com, c, responses


def check_commitment(generators, com, c, responses):
    l = len(generators)
    R = com ** c
    for i in range(l):
        R *= generators[i] ** responses[i]

    new_challenge = hashlib.sha256()
    for generator in generators:
        new_challenge.update(generator.to_binary())
    new_challenge.update(R.to_binary())
    c1 = Bn.from_binary(new_challenge.digest()).int()

    return c == c1
