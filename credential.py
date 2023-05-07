"""
Skeleton credential module for implementing PS credentials

The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.

You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use `jsonpickle` serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.

We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""
from typing import Any

from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G2

from credential_utils import *
from zkp_utils import *


######################
## SIGNATURE SCHEME ##
######################


def generate_key(
        attributes: List[Any]
    ) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """

    if len(attributes) == 0:
        raise ValueError("The length of the attribute vector is zero")

    # length of the message vector
    L = len(attributes)

    # pick x and y from integers modulo p (the group order)
    x = G1.order().random()
    y = [G1.order().random() for _ in range(L)]

    # pick random generators g for G1 and g_tilde for G2 (not random here)
    g = G1.generator()
    g_tilde = G2.generator()

    # compute X, X_tilde
    X = g ** x
    X_tilde = g_tilde ** x

    # compute Y, Y_tilde
    Y = [g ** y_i for y_i in y]
    Y_tilde = [g_tilde ** y_i for y_i in y]

    # return the secret and public key
    return SecretKey(x, X, y), PublicKey(g, Y, g_tilde, X_tilde, Y_tilde)


def sign(
        sk: SecretKey,
        msgs: List[bytes]
    ) -> Signature:
    """ Sign the vector of messages `msgs` """

    # check that the length of the message vector is not zero
    if len(msgs) == 0:
        raise ValueError("The length of the message vector is zero")

    # check that the length of the message vector is L
    if len(msgs) != len(sk.y):
        raise ValueError("The length of the message vector is not L")
    
    # map msgs to Z_p 
    # m = [G1.hash_to_point(msg) for msg in msgs] doesn't work
    m = [bytes_to_Z_p(msg) for msg in msgs]

    # pick random generator h for G1 (not random here)
    # h = G1.generator()
    # h must not be identity element
    # h = G1_no_identity() might not be needed as G1.generator() always returns the same generator which is never the identity element
    h = G1_random_generator()

    # compute exponent
    # if h is G1.generator() then this can be done more efficiently with wprod()
    exp = sk.x + sum([sk.y[i] * m[i] for i in range(len(m))])

    return Signature(h, h ** exp)


def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes]
    ) -> bool:
    """ Verify the signature on a vector of messages """

    # check that the length of the message vector is not zero
    if len(msgs) == 0:
        raise ValueError("The length of the message vector is zero")

    # check that the length of the message vector is L
    if len(msgs) != len(pk.Y):
        raise ValueError("The length of the message vector is not L")

    # map msgs to Z_p 
    # m = [G1.hash_to_point(msg) for msg in msgs] doesn't work
    m = [bytes_to_Z_p(msg) for msg in msgs]

    # compute product X_tilde * Y_tilde[0]^m[0] * ... * Y_tilde[L-1]^m[L-1]
    product = pk.X_tilde
    for i in range(len(m)):
        product *= pk.Y_tilde[i] ** m[i]
    
    return signature.sigma_1 != G1.unity() and signature.sigma_1.pair(product) == signature.sigma_2.pair(pk.g_tilde)


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##

def create_issue_request(
        pk: PublicKey,
        user_attributes: List[Attribute]
    ) -> Tuple[IssueRequest, Bn]:
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """
    # pick random t from integers modulo p
    t = G1.order().random()

    # compute Pedersen commitment
    C = pk.g ** t
    generators = [pk.g]
    prover_inputs = [t]
    for attr in user_attributes:
        prover_input = bytes_to_Z_p(attr.to_bytes()) # TODO: check if it makes sense to convert the whole object to bytes or just the value?
        generator = pk.Y[attr.index]
        C *= generator ** prover_input

        generators.append(generator)
        prover_inputs.append(prover_input)

    # compute a non-interactive proof pi
    c, s = generate_zkp(generators, prover_inputs, C)
    pi = ZKProof(generators, c, s)

    return IssueRequest(C, pi), t


def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: List[Attribute]
) -> BlindSignature:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """

    # verify the validity of the proof pi with respect to the commitment C and abort if invalid
    pi = request.pi
    if not verify_zkp(request.C, pi.generators, pi.c, pi.s):
        raise ZKPVerificationError("ZKP verification failed")

    # pick random u from integers modulo p
    u = G1.order().random()

    # compute product X * C * Y[i]^attr[i] for all i in I
    product = sk.X * request.C
    for attr in issuer_attributes:
        product *= pk.Y[attr.index] ** bytes_to_Z_p(attr.to_bytes())

    return BlindSignature(pk.g ** u, product ** u)


def obtain_credential(
        pk: PublicKey,
        response: BlindSignature,
        t: Bn
    ) -> Signature:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    return Signature(response.sigma_1, response.sigma_2 / (response.sigma_1 ** t))


## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: List[Attribute],
        message: bytes
    ) -> DisclosureProof:
    """ Create a disclosure proof """

    # compute Pedersen commitment (RHS)
    C = credential.sigma_1.pair(pk.g_tilde) ** credential.t
    generators = [credential.sigma_1.pair(pk.g_tilde)]
    prover_inputs = [credential.t]

    for hidden_attr in hidden_attributes:
        idx = hidden_attr.index
        generator = credential.sigma_1.pair(pk.Y_tilde[idx])
        prover_input = bytes_to_Z_p(hidden_attr.to_bytes())
        C *= generator ** prover_input

        generators.append(generator)
        prover_inputs.append(prover_input)
    
    # compute a non-interactive proof pi
    c, s = generate_zkp(generators, prover_inputs, C)
    pi = ZKProof(generators, c, s)

    return DisclosureProof(pi, credential)


def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        message: bytes,
        # TODO: check how can be retrieved otherwise? I think it is okay like this.
        disclosed_attributes: List[Attribute]
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    # disclosure proof
    credential = disclosure_proof.credential_showed
    pi = disclosure_proof.pi

    # compute Pedersen commitment (LHS)
    # the user does not send the Pedersen commitment, the verifier can compute it from the disclosed attributes
    # numerator
    numerator = credential.sigma_2.pair(pk.g_tilde)
    for disclosed_attr in disclosed_attributes:
        idx = disclosed_attr.index
        numerator *= credential.sigma_1.pair(pk.Y_tilde[idx]) ** (bytes_to_Z_p(disclosed_attr.to_bytes()).int_neg())
    # denominator
    denominator = credential.sigma_1.pair(pk.X_tilde)
    # Pedersen commitment
    C = numerator / denominator

    # verify ZKP
    return credential.sigma_1 != G1.unity() and verify_zkp(C, pi.generators, pi.c, pi.s)
