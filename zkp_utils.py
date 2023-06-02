""" Zero-knowledge proof utilities 
This module contains utilities for generating and verifying zero-knowledge proofs. 

The following notation is used throughout this module:
- generators (a.k.a. public keys)
        g_0, g_1, ..., g_k
- prover_input (a.k.a. prover secrets)
        a_0, a_1, ..., a_k
- com (a.k.a. Pedersen commitment) 
        com = g_0^a_0 * g_1^a_1 * ... * g_k^a_k
- randoms 
        r_0, r_1, ..., r_k
- R (a.k.a. ZKP commitment)
        R = g_0^r_0 * g_1^r_1 * ... * g_k^r_k
- c (a.k.a. ZKP challenge)
        H(generators || com || R || message (optional))
- s (a.k.a. ZKP response)
        [r_0 - c * a_0, r_1 - c * a_1, ..., r_k - c * a_k]

There are two actors in a zero-knowledge proof: a prover and a verifier.

Prover:
- Given a list of generators, a list of prover inputs, a Pedersen commitment (com) and an optional message,
- Generates a ZKP commitment (R): randoms, R <- get_zkp_commitment(generators),
- Generates a ZKP challenge (c): c <- get_zkp_challenge(generators, com, R, message (optional)),
- Generates a ZKP response (s): s <- get_zkp_response(randoms, c, prover_input)

Option 1 (current implementation):
Prover => Verifier:
- com, generators (public)
- c (ZKP challenge)
- s (ZKP response)
- message (optional)

Verifier:
- Given a list of generators, a Pedersen commitment (com), a ZKP challenge (c), a ZKP response (s) and an optional message, 
- Compute R' = com^c * g_0^s_0 * g_1^s_1 * ... * g_k^s_k,
- Compute c' = H(generators || com || R' || message (optional)),
- Accept if and only if c == c'

Option 2:
Prover => Verifier:
- com, generators (public)
- R (ZKP commitment)
- s (ZKP response)
- message (optional)

Verifier:
- Given a list of generators, a Pedersen commitment (com), a ZKP commitment (R), a ZKP response (s) and an optional message,
- Compute c' = H(generators || com || R || message (optional)),
- Accept only if R == com^c' * g_0^s_0 * g_1^s_1 * ... * g_k^s_k
"""
import hashlib
from typing import Any, List, Tuple

from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1

from credential_utils import bytes_to_Z_p


def get_zkp_commitment(
        generators : List[Any] # the type is Any because can be G1Element or GTElement
        ) -> Tuple[List[Bn], Any]:
    """ Generate a commitment """
    # pick a list of random numbers from integers modulo p
    randoms = [G1.order().random() for _ in generators]
    # generate ZKP commitment
    R = generators[0] ** randoms[0]
    for generator, random in zip(generators[1:], randoms[1:]):
        R *= generator ** random

    return randoms, R

def get_zkp_challenge(
        generators : List[Any],
        com : Bn,
        R : Any,
        message: bytes = None
        ) -> Bn:
        """ Generate a non-interactive challenge according to the Fiat-Shamir heuristic """
        """ Optional message in case of signature """
        c = hashlib.sha256()
        for generator in generators:
                c.update(generator.to_binary())
        c.update(com.to_binary())
        c.update(R.to_binary())
        if message != None:
            c.update(message)
        return bytes_to_Z_p(c.digest())

def get_zkp_response(
        randoms: List[Bn],
        c: Bn,
        prover_input: List[Bn]
        ) -> List[Bn]:
        """ Generate a response """
        return [(random - c * input).mod(G1.order()) for random, input in zip(randoms, prover_input)]

def generate_zkp(
        generators: List[Any],
        prover_input: List[Bn],
        com: Any,
        message: bytes = None
        ) -> Tuple[Bn, List[Bn]]:
        """ Generate a zero-knowledge proof """
        # generate ZKP commitment
        randoms, R = get_zkp_commitment(generators)
        # generate ZKP challenge
        c = get_zkp_challenge(generators, com, R) if message == None else get_zkp_challenge(generators, com, R, message)
        # generate ZKP response
        s = get_zkp_response(randoms, c, prover_input)
        return c, s
        
def verify_zkp(
        com: Any,
        generators: List[Any],
        c: Bn,
        s: List[Bn],
        message: bytes = None
        ) -> bool:
        """ Verify a zero-knowledge proof """
        # generate R'
        R_prime = com ** c
        for generator, resp in zip(generators, s):
                R_prime *= generator ** resp
        # generate c'
        c_prime = get_zkp_challenge(generators, com, R_prime) if message == None else get_zkp_challenge(generators, com, R_prime, message)
        # accept if and only if c == c'
        return c == c_prime

class ZKPVerificationError(Exception):
        """ Exception raised when a zero-knowledge proof is invalid """
        pass
