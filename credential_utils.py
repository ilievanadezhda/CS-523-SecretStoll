import hashlib
import os
from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1
from typing import List, Any


class Attribute:
    def __init__(self, index, key, value):
        self.index = index
        self.key = key
        self.value = value

    def to_formatted_string(self):
        return "{}:{}".format(str(self.key), str(self.value))

    def to_bytes(self) -> bytes:
        return bytes(self.to_formatted_string(), "utf-8")
    
    def __repr__(self):
        return "[{}]: {},{}".format(str(self.index), self.key, self.value)

class PublicKey:
    """ Public key of the signer/issuer"""
    def __init__(self, g, Y, g_tilde, X_tilde, Y_tilde, attr_indices_dict: dict[str, int]):
        self.g = g
        self.Y = Y
        self.g_tilde = g_tilde
        self.X_tilde = X_tilde
        self.Y_tilde = Y_tilde
        self.attr_indices_dict = attr_indices_dict

class SecretKey:
    """ Secret key of the signer/issuer"""
    def __init__(self, x, X, y):
        self.x = x
        self.X = X
        self.y = y

class AnonymousCredential:
    """ Anonymized signature on a vector of messages"""
    def __init__(self, sigma_1, sigma_2, t):
        self.sigma_1 = sigma_1
        self.sigma_2 = sigma_2
        self.t = t

class Signature:
    """ Signature on a vector of messages"""
    def __init__(self, sigma_1, sigma_2):
        self.sigma_1 = sigma_1
        self.sigma_2 = sigma_2

    def anonymize(self) -> AnonymousCredential:
        r, t = G1.order().random(), G1.order().random()
        return AnonymousCredential(self.sigma_1 ** r, (self.sigma_2 * self.sigma_1 ** t) ** r, t)

class BlindSignature:
    def __init__(self, sigma_1, sigma_2):
        self.sigma_1 = sigma_1
        self.sigma_2 = sigma_2

class ZKProof:
    def __init__(self, generators, c, s):
        self.generators = generators
        self.c = c
        self.s = s

class IssueRequest:
    def __init__(self, C, pi):
        self.C = C
        self.pi = pi

class DisclosureProof:
    def __init__(self, pi: ZKProof, credential_showed: AnonymousCredential):
        self.pi = pi
        self.credential_showed = credential_showed

class State:
    """ Used in the client to store state between prepare_registration
    and process_registration_response """
    def __init__(self, t: Bn):
        self.t = t

#######################################
## CREDENTIAL SCHEME HELPER FUNCTIONS##
#######################################

def bytes_to_Z_p(m):
    """ Convert bytes to Z_p (the order of G1) """
    return Bn.from_binary(hashlib.sha256(m).digest()).mod(G1.order())


def G1_random_generator():
    """ Return a random generator/non-unity element of G1 """
    # pick a random element from G1
    element = G1.hash_to_point(os.urandom(32))
    # if the element is the identity, pick another one
    while element == G1.unity():
        element = G1.hash_to_point(os.urandom(32))
    return element

#################
## in memoriam ##
#################

# def pedersen_commitment(secrets: List[int]):
#     p = G1.order()
#     l = len(secrets)

#     generators = [G1.generator() for _ in secrets]
#     randoms = [G1.order().random() for _ in secrets]

#     com = generators[0] ** secrets[0]
#     R = generators[0] ** randoms[0]
#     for gen_i in range(1, l):
#         com *= generators[gen_i] ** secrets[gen_i]
#         R *= generators[gen_i] ** randoms[gen_i]

#     challenge = hashlib.sha256()
#     for generator in generators:
#         challenge.update(generator.to_binary())
#     challenge.update(R.to_binary())

#     c = Bn.from_binary(challenge.digest()).int()

#     responses = [(randoms[i] - c * secrets[i]) % p for i in range(l)]

#     return generators, com, c, responses


# def check_commitment(generators, com, c, responses):
#     l = len(generators)
#     R = com ** c
#     for i in range(l):
#         R *= generators[i] ** responses[i]

#     new_challenge = hashlib.sha256()
#     for generator in generators:
#         new_challenge.update(generator.to_binary())
#     new_challenge.update(R.to_binary())
#     c1 = Bn.from_binary(new_challenge.digest()).int()

#     return c == c1

# class Pi:
#     def __init__(self, R, commitment, challenge, generators: List[Any], response: List[Any]):
#         self.R = R
#         self.commitment = commitment
#         self.challenge = challenge
#         self.generators = generators
#         self.response = response

# class AttributeMap:
#     """ A map from attribute names (0, 1 ... L-1) to bytes """
#     def __init__(self, L):
#         self.L = L
#         self.map = {}
#         for i in range(L):
#             self.map[i] = None

#     def get_attribute(self, key):
#         return self.map[key]

#     def set_attribute(self, key, value):
#         if 0 <= key < self.L:
#             self.map[key] = value
#         else:
#             raise ValueError("Attribute index out of range")

#     def get_attributes(self):
#         """ Return a list of non-empty attributes """
#         return [(key, self.map[key]) for key in self.map if self.map[key] is not None]

#     def print(self):
#         for key in self.map:
#             print(key, self.map[key])
