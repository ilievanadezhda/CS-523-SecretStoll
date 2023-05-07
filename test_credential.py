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

    user_attributes = [Attribute(0, "key0", b'0'), Attribute(1, "key1", b'1'), Attribute(2, "key2", b'2')]
    issuer_attributes = [Attribute(3, "key3", b'3'), Attribute(4, "key4", b'4')]

    issue_request, t = create_issue_request(pk, user_attributes)
    blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)
    signature = obtain_credential(pk, blind_signature, t)

    user_attributes_bytes = [attr.to_bytes() for attr in user_attributes]
    issuer_attributes_bytes = [attr.to_bytes() for attr in issuer_attributes]
    attributes = user_attributes_bytes + issuer_attributes_bytes
    assert verify(pk, signature, attributes)


@pytest.mark.xfail(raises=AssertionError)
def test_failure_issuance_wrong_attr():
    L = 5
    sk, pk = generate_key([b"0"] * L)

    user_attributes = [Attribute(0, "key0", b'0'), Attribute(1, "key1", b'1'), Attribute(2, "key2", b'2')]
    issuer_attributes = [Attribute(3, "key3", b'3'), Attribute(4, "key4", b'4')]

    issue_request, t = create_issue_request(pk, user_attributes)
    blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)
    signature = obtain_credential(pk, blind_signature, t)

    user_attributes = [Attribute(0, "key0", b'hello'), Attribute(1, "key1", b'1'), Attribute(2, "key2", b'2')]
    user_attributes_bytes = [attr.to_bytes() for attr in user_attributes]
    issuer_attributes_bytes = [attr.to_bytes() for attr in issuer_attributes]
    attributes = user_attributes_bytes + issuer_attributes_bytes
    assert verify(pk, signature, attributes)


@pytest.mark.xfail(raises=ZKPVerificationError)
def test_failure_issuance_wrong_proof():
    L = 5
    sk, pk = generate_key([b"0"] * L)

    user_attributes = [Attribute(0, "key0", b'0'), Attribute(1, "key1", b'1'), Attribute(2, "key2", b'2')]
    issuer_attributes = [Attribute(3, "key3", b'3'), Attribute(4, "key4", b'4')]

    issue_request, t = create_issue_request(pk, user_attributes)
    # change pi
    issue_request.pi.generators.append(G1.generator() ** G1.order().random())
    issue_request.pi.s.append(G1.order().random())

    sign_issue_request(sk, pk, issue_request, issuer_attributes)
    
def test_disclosure_proof_both_issuer_user_attr():
    sk, pk = generate_key([b"0",b"1"])
    user_attributes = [Attribute(0, "secret_key", "value0")]
    issuer_attributes = [Attribute(1, "rest", "true")]
    issue_req, t = create_issue_request(pk, user_attributes)
    signature = sign_issue_request(sk, pk, issue_req, issuer_attributes)
    cred = obtain_credential(pk, signature, t)
    
    anonym_cred = cred.anonymize()
    dis_proof = create_disclosure_proof(pk, anonym_cred, user_attributes, b"1")
    assert verify_disclosure_proof(pk, dis_proof, b"1", issuer_attributes)
                    
def test_disclosure_proof_user_attr_only():
    sk, pk = generate_key([b"0",b"1"])
    user_attributes = [Attribute(0, "secret_key", "value0"), Attribute(1, "username", "value1")]
    issue_req, t = create_issue_request(pk, user_attributes)
    signature = sign_issue_request(sk, pk, issue_req, [])
    cred = obtain_credential(pk, signature, t)
    
    anonym_cred = cred.anonymize()
    dis_proof = create_disclosure_proof(pk, anonym_cred, user_attributes, b"1")
    assert verify_disclosure_proof(pk, dis_proof, b"1", [])              

def test_disclosure_proof_issuer_attr_only():
    sk, pk = generate_key([b"0",b"1"])
    issuer_attributes = [Attribute(0, "key0", "value0"), Attribute(1, "key1", "value1")]
    issue_req, t = create_issue_request(pk, [])
    signature = sign_issue_request(sk, pk, issue_req, issuer_attributes)
    cred = obtain_credential(pk, signature, t)
    
    anonym_cred = cred.anonymize()
    dis_proof = create_disclosure_proof(pk, anonym_cred, [], b"1")
    assert verify_disclosure_proof(pk, dis_proof, b"1", issuer_attributes)
    
def test_disclosure_proof_custom_disclosure_1():
    sk, pk = generate_key([b"0",b"1",b"2"])
    attr_1 = Attribute(0, "username", "value0")
    attr_2, attr_3 = Attribute(1, "rest", "true"), Attribute(2, "dojo", "true")
    user_attributes = [attr_1]
    issuer_attributes = [attr_2, attr_3]
    issue_req, t = create_issue_request(pk, user_attributes)
    signature = sign_issue_request(sk, pk, issue_req, issuer_attributes)
    cred = obtain_credential(pk, signature, t)
    
    anonym_cred = cred.anonymize()
    dis_proof = create_disclosure_proof(pk, anonym_cred, [attr_1, attr_2], b"1")
    assert verify_disclosure_proof(pk, dis_proof, b"1", [attr_3])

def test_disclosure_proof_custom_disclosure_2():
    sk, pk = generate_key([b"0",b"1",b"2",b"3",b"4"])
    attr_1, attr_2 = Attribute(0, "secret_key", "value0"), Attribute(1, "username", "value1")
    attr_3, attr_4, attr_5 = Attribute(2, "rest", "true"), Attribute(3, "dojo", "true"), Attribute(4, "bar", "false")
    user_attributes = [attr_1, attr_2]
    issuer_attributes = [attr_3, attr_4, attr_5]
    issue_req, t = create_issue_request(pk, user_attributes)
    signature = sign_issue_request(sk, pk, issue_req, issuer_attributes)
    cred = obtain_credential(pk, signature, t)
    
    anonym_cred = cred.anonymize()
    dis_proof = create_disclosure_proof(pk, anonym_cred, [attr_1, attr_2, attr_3], b"1")
    assert verify_disclosure_proof(pk, dis_proof, b"1", [attr_4, attr_5])       
    