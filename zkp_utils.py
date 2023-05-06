import hashlib
from typing import List, Tuple

from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G1Element

from credential_utils import bytes_to_Z_p


def get_zkp_commitment(
        generators : List[G1Element]
        ) -> Tuple[G1Element, List[Bn]]:
    """ Generate a commitment """
    # pick a list of random numbers from integers modulo p
    randoms = [G1.order().random() for _ in generators]

    # compute commitment
    R = generators[0] ** randoms[0]
    for generator, random in zip(generators[1:], randoms[1:]):
        R *= generator ** random

    return randoms, R

def get_zkp_challenge(
        generators : List[G1Element],
        com : Bn,
        R : G1Element
        ) -> Bn:
        """ Generate a non-interactive challenge according to the Fiat-Shamir heuristic """
        c = hashlib.sha256()
        for generator in generators:
                c.update(generator.to_binary())
        c.update(com.to_binary())
        c.update(R.to_binary())
        return bytes_to_Z_p(c.digest())

def get_zkp_response(
        randoms: List[Bn],
        c: Bn,
        prover_input: List[Bn]
        ) -> List[Bn]:
        """ Generate a response """
        return [(random - c * input).mod(G1.order()) for random, input in zip(randoms, prover_input)]

def verify_zkp(
        R: G1Element,
        com: G1Element,
        c: Bn,
        generators: List[G1Element],
        response: List[Bn]
        ) -> bool:
        """ Verify a zero-knowledge proof """
        lhs = R
        rhs = com**c
        for generator, resp in zip(generators, response):
                rhs *= generator ** resp

        return lhs == rhs and get_zkp_challenge(generators, com, rhs) == c
