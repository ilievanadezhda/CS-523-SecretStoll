import pytest

from credential import *
from credential_utils import *
from zkp_utils import *

def test_zkp_1():
    L = 5
    sk, pk = generate_key([b"0"] * L)

    user_attributes = AttributeMap(L)
    user_attributes.set_attribute(0, b'hello')
    user_attributes.set_attribute(1, b'1')
    user_attributes.set_attribute(2, b'2')

    # compute commitment
    t = G1.order().random()
    C = pk.g ** t
    for (i, attr) in user_attributes.get_attributes():
        C *= pk.Y[i] ** bytes_to_Z_p(attr)

    # generators
    generators = [pk.g] + [pk.Y[i] for i, _ in user_attributes.get_attributes()]
    # prover input
    prover_inputs = [t] + [bytes_to_Z_p(attr) for _, attr in user_attributes.get_attributes()]

    # zkp
    randoms, R = get_zkp_commitment(generators)
    c = get_zkp_challenge(generators, C, R)
    response = get_zkp_response(randoms, c, prover_inputs)
    assert verify_zkp(R, C, c, generators, response)

@pytest.mark.xfail(raises=AssertionError)
def test_zkp_2():
    L = 5
    sk, pk = generate_key([b"0"] * L)

    user_attributes = AttributeMap(L)
    user_attributes.set_attribute(0, b'hello')
    user_attributes.set_attribute(1, b'1')
    user_attributes.set_attribute(2, b'2')

    # compute commitment
    t = G1.order().random()
    C = pk.g ** t
    for (i, attr) in user_attributes.get_attributes():
        C *= pk.Y[i] ** bytes_to_Z_p(attr)

    # generators
    generators = [pk.g] + [pk.Y[i] for i, _ in user_attributes.get_attributes()]
    # prover input
    prover_inputs = [t] + [bytes_to_Z_p(attr) for _, attr in user_attributes.get_attributes()]

    # zkp
    randoms, R = get_zkp_commitment(generators)
    c = get_zkp_challenge(generators, C, R)
    response = get_zkp_response(randoms, c, prover_inputs)

    # change response
    response[0] = Bn(10)

    assert verify_zkp(R, C, c, generators, response)