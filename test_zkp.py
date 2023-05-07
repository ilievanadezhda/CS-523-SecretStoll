import pytest

from credential import *
from credential_utils import *
from zkp_utils import *

def test_zkp_1():
    L = 5
    sk, pk = generate_key([b"0"] * L)
    user_attributes = [Attribute(0, "key0", b'0'), Attribute(1, "key1", b'1'), Attribute(2, "key2", b'2')]

    # compute commitment
    t = G1.order().random()
    C = pk.g ** t
    generators = [pk.g]
    prover_inputs = [t]
    for attr in user_attributes:
        prover_input = bytes_to_Z_p(attr.to_bytes())
        generator = pk.Y[attr.index]
        C *= generator ** prover_input

        generators.append(generator)
        prover_inputs.append(prover_input)

    # zkp
    randoms, R = get_zkp_commitment(generators)
    c = get_zkp_challenge(generators, C, R)
    s = get_zkp_response(randoms, c, prover_inputs)
    assert verify_zkp(C, generators, c, s)

@pytest.mark.xfail(raises=AssertionError)
def test_zkp_2():
    L = 5
    sk, pk = generate_key([b"0"] * L)
    user_attributes = [Attribute(0, "key0", b'hello'), Attribute(1, "key1", b'1'), Attribute(2, "key2", b'2')]

    # compute commitment
    t = G1.order().random()
    C = pk.g ** t
    generators = [pk.g]
    prover_inputs = [t]
    for attr in user_attributes:
        prover_input = bytes_to_Z_p(attr.to_bytes())
        generator = pk.Y[attr.index]
        C *= generator ** prover_input

        generators.append(generator)
        prover_inputs.append(prover_input)

    # zkp
    randoms, R = get_zkp_commitment(generators)
    c = get_zkp_challenge(generators, C, R)
    s = get_zkp_response(randoms, c, prover_inputs)

    # change response
    s[0] = Bn(10)

    assert verify_zkp(C, generators, c, s)