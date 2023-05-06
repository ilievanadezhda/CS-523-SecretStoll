import pytest
from petrelic.multiplicative.pairing import G1

from credential import *
from credential_utils import *


def test_success_signature_verify():
    message_vec = [b"hello", b"world"]
    sk, pk = generate_key(message_vec)
    signature = sign(sk, message_vec)
    assert verify(pk, signature, message_vec)


@pytest.mark.xfail(raises=ValueError)
def test_failure_generate_no_attr():
    message_vec = []
    generate_key(message_vec)


@pytest.mark.xfail(raises=AssertionError)
def test_failure_signature_verify():
    message_vec_1 = [b"hello", b"world"]
    message_vec_2 = [b"hello", b"world!"]
    sk, pk = generate_key(message_vec_1)
    signature = sign(sk, message_vec_1)
    assert verify(pk, signature, message_vec_2)


@pytest.mark.xfail(raises=ValueError)
def test_failure_verify_attr_number():
    message_vec_1 = [b"hello", b"world"]
    message_vec_2 = [b"hello", b"world", b"!"]
    sk, pk = generate_key(message_vec_1)
    signature = sign(sk, message_vec_1)
    assert verify(pk, signature, message_vec_2)


@pytest.mark.xfail(raises=ValueError)
def test_failure_verify_no_attr():
    message_vec_1 = [b"hello", b"world"]
    sk, pk = generate_key(message_vec_1)
    signature = sign(sk, message_vec_1)
    assert verify(pk, signature, [])


@pytest.mark.xfail(raises=ValueError)
def test_failure_sign_no_attr():
    message_vec = [b"hello"]
    sk, pk = generate_key(message_vec)
    sign(sk, [])


@pytest.mark.xfail(raises=ValueError)
def test_failure_sign_attr_num():
    message_vec_1 = [b"hello", b"world"]
    message_vec_2 = [b"hello", b"world", b"!"]
    sk, pk = generate_key(message_vec_1)
    sign(sk, message_vec_2)


def test_success_issuance():
    L = 5
    sk, pk = generate_key([b"0"] * L)

    user_attributes = AttributeMap(L)
    user_attributes.set_attribute(0, b'0')
    user_attributes.set_attribute(1, b'1')
    user_attributes.set_attribute(2, b'2')

    issuer_attributes = AttributeMap(L)
    issuer_attributes.set_attribute(3, b'3')
    issuer_attributes.set_attribute(4, b'4')

    issue_request, t = create_issue_request(pk, user_attributes)
    blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)
    signature = obtain_credential(pk, blind_signature, t)

    attributes = [b'0', b'1', b'2', b'3', b'4']
    assert verify(pk, signature, attributes)


@pytest.mark.xfail(raises=AssertionError)
def test_failure_issuance_wrong_proof():
    L = 5
    sk, pk = generate_key([b"0"] * L)

    user_attributes = AttributeMap(L)
    user_attributes.set_attribute(0, b'0')
    user_attributes.set_attribute(1, b'1')
    user_attributes.set_attribute(2, b'2')

    issuer_attributes = AttributeMap(L)
    issuer_attributes.set_attribute(3, b'3')
    issuer_attributes.set_attribute(4, b'4')

    issue_request, t = create_issue_request(pk, user_attributes)
    # change pi
    issue_request.pi.generators.append(G1.generator() ** G1.order().random())
    issue_request.pi.response.append(G1.order().random())

    sign_issue_request(sk, pk, issue_request, issuer_attributes)


@pytest.mark.xfail(raises=AssertionError)
def test_failure_issuance_wrong_attr():
    L = 5
    sk, pk = generate_key([b"0"] * L)

    user_attributes = AttributeMap(L)
    user_attributes.set_attribute(0, b'hello')
    user_attributes.set_attribute(1, b'1')
    user_attributes.set_attribute(2, b'2')

    issuer_attributes = AttributeMap(L)
    issuer_attributes.set_attribute(3, b'3')
    issuer_attributes.set_attribute(4, b'4')

    issue_request, t = create_issue_request(pk, user_attributes)
    blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)
    signature = obtain_credential(pk, blind_signature, t)

    attributes = [b'0', b'1', b'2', b'3', b'4']
    assert verify(pk, signature, attributes)
