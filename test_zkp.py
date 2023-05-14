import pytest

from credential import *
from credential_utils import *
from zkp_utils import *

def test_success_zkp_no_message_1():
    sk, pk = generate_key(["key"] * 5)
    user_attributes = [Attribute(0, "key0", "value0"), Attribute(1, "key1", "value1"), Attribute(2, "key2", "value2")]
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
    # zkp protocol
    randoms, R = get_zkp_commitment(generators)
    c = get_zkp_challenge(generators, C, R)
    s = get_zkp_response(randoms, c, prover_inputs)
    assert verify_zkp(C, generators, c, s)

def test_success_zkp_no_message_2():
    sk, pk = generate_key(["key"] * 5)
    user_attributes = [Attribute(0, "key0", "value0"), Attribute(1, "key1", "value1"), Attribute(2, "key2", "value2")]
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
    # zkp protocol
    c, s = generate_zkp(generators, prover_inputs, C)
    assert verify_zkp(C, generators, c, s)

def test_success_zkp_message():
    sk, pk = generate_key(["key"] * 5)
    user_attributes = [Attribute(0, "key0", "value0"), Attribute(1, "key1", "value1"), Attribute(2, "key2", "value2")]
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
    # zkp protocol
    c, s = generate_zkp(generators, prover_inputs, C, b"hello world")
    assert verify_zkp(C, generators, c, s, b"hello world")

@pytest.mark.xfail(raises=AssertionError)
def test_failure_zkp_no_message_change_challenge():
    sk, pk = generate_key(["key"] * 5)
    user_attributes = [Attribute(0, "key0", "value0"), Attribute(1, "key1", "value1"), Attribute(2, "key2", "value2")]
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
    # zkp protocol 
    c, s = generate_zkp(generators, prover_inputs, C)
    # change challenge
    c_random = G1.order().random()
    while c_random == c:
        c_random = G1.order().random()
    assert verify_zkp(C, generators, c_random, s)

@pytest.mark.xfail(raises=AssertionError)
def test_failure_zkp_no_message_change_response():
    sk, pk = generate_key(["key"] * 5)
    user_attributes = [Attribute(0, "key0", "value0"), Attribute(1, "key1", "value1"), Attribute(2, "key2", "value2")]
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
    # zkp protocol 
    c, s = generate_zkp(generators, prover_inputs, C)
    # change s[0]
    s_random = G1.order().random()
    while s_random == s[0]:
        s_random = G1.order().random()
    s = [s_random] + s[1:]
    assert verify_zkp(C, generators, c, s)

@pytest.mark.xfail(raises=AssertionError)
def test_failure_zkp_different_message():
    sk, pk = generate_key(["key"] * 5)
    user_attributes = [Attribute(0, "key0", "value0"), Attribute(1, "key1", "value1"), Attribute(2, "key2", "value2")]
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
    # zkp protocol
    c, s = generate_zkp(generators, prover_inputs, C, b"hello world")
    assert verify_zkp(C, generators, c, s, b"hello ATOPET!")

@pytest.mark.xfail(raises=AssertionError)
def test_failure_zkp_empty_message_1():
    sk, pk = generate_key(["key"] * 5)
    user_attributes = [Attribute(0, "key0", "value0"), Attribute(1, "key1", "value1"), Attribute(2, "key2", "value2")]
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
    # zkp protocol
    c, s = generate_zkp(generators, prover_inputs, C)
    assert verify_zkp(C, generators, c, s, b"hello ATOPET!")

@pytest.mark.xfail(raises=AssertionError)
def test_failure_zkp_enpty_message_2():
    sk, pk = generate_key(["key"] * 5)
    user_attributes = [Attribute(0, "key0", "value0"), Attribute(1, "key1", "value1"), Attribute(2, "key2", "value2")]
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
    # zkp protocol
    c, s = generate_zkp(generators, prover_inputs, C, b"hello world")
    assert verify_zkp(C, generators, c, s)
