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

from typing import Any, List, Tuple

from serialization import jsonpickle

from petrelic.multiplicative.pairing import G1, G2, GT
from credential_utils import *

# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!

# SecretKey = Any
# PublicKey = Any
# Signature = Any
Attribute = Any
AttributeMap = Any
IssueRequest = Any
BlindSignature = Any
AnonymousCredential = Any
DisclosureProof = Any


######################
## SIGNATURE SCHEME ##
######################


def generate_key(
        attributes: List[Attribute]
    ) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """

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
    
    # map msgs to WHAT? 
    # m = [G1.hash_to_point(msg) for msg in msgs] doesn't work
    m = [bytes_to_Z_p(msg, G1.order()) for msg in msgs]

    # pick random generator h for G1 (not random here)
    h = G1.generator()

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

    # map msgs to WHAT? 
    # m = [G1.hash_to_point(msg) for msg in msgs] doesn't work
    m = [bytes_to_Z_p(msg, G1.order()) for msg in msgs]

    # compute product X_tilde * Y_tilde[0]^m[0] * ... * Y_tilde[L-1]^m[L-1]
    product = pk.X_tilde
    for i in range(len(m)):
        product *= pk.Y_tilde[i] ** m[i]
    
    return signature.sigma_1 != G1.unity and signature.sigma_1.pair(product) == signature.sigma_2.pair(pk.g_tilde)



#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##

def create_issue_request(
        pk: PublicKey,
        user_attributes: AttributeMap
    ) -> IssueRequest:
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """
    # pick random t from integers modulo p
    t = G1.order().random()

    # compute commitment
    commitment = pk.g ** t
    for i in user_attributes.keys: # TODO: how does the AttributeMap look like?
        commitment *= pk.Y[i] ** user_attributes[i]
    
    raise NotImplementedError()


def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
    ) -> BlindSignature:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    raise NotImplementedError()


def obtain_credential(
        pk: PublicKey,
        response: BlindSignature
    ) -> AnonymousCredential:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    raise NotImplementedError()


## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: List[Attribute],
        message: bytes
    ) -> DisclosureProof:
    """ Create a disclosure proof """
    raise NotImplementedError()


def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        message: bytes
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    raise NotImplementedError()
