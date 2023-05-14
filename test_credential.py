import pytest
from petrelic.multiplicative.pairing import G1

from credential import *
from credential_utils import *
import string

""" Helper functions """
def encode_to_bytes(strings: List[str]):
    return [x.encode() for x in strings]

""" Key generation tests """
@pytest.mark.xfail(raises=ValueError)
def test_failure_generate_key_no_attr():
    message_vec = []
    generate_key(message_vec)   

""" Sign tests """
@pytest.mark.xfail(raises=ValueError)
def test_failure_sign_empty_message():
    message_vec = ["hello", "world"]
    sk, pk = generate_key(message_vec)
    sign(sk, encode_to_bytes([]))

@pytest.mark.xfail(raises=ValueError)
def test_failure_sign_different_message_length():
    message_vec_1 = ["hello", "world"]
    message_vec_2 = ["hello", "world", "!"]
    sk, pk = generate_key(message_vec_1)
    sign(sk, encode_to_bytes(message_vec_2))

""" Sign and verify tests """
def test_success_sign_verify():
    message_vec = ["hello", "world"]
    sk, pk = generate_key(message_vec)
    signature = sign(sk, encode_to_bytes(message_vec))
    assert verify(pk, signature, encode_to_bytes(message_vec))

@pytest.mark.xfail(raises=AssertionError)
def test_failure_sign_verify_different_messages():
    message_vec_1 = ["hello", "world"]
    message_vec_2 = ["hello", "world!"]
    sk, pk = generate_key(message_vec_1)
    signature = sign(sk, encode_to_bytes(message_vec_1))
    assert verify(pk, signature, encode_to_bytes(message_vec_2))

@pytest.mark.xfail(raises=ValueError)
def test_failure_sign_verify_different_message_length():
    message_vec_1 = ["hello", "world"]
    message_vec_2 = ["hello", "world", "!"]
    sk, pk = generate_key(message_vec_1)
    signature = sign(sk, encode_to_bytes(message_vec_1))
    assert verify(pk, signature, encode_to_bytes(message_vec_2))

@pytest.mark.xfail(raises=ValueError)
def test_failure_sign_verify_empty_message():
    message_vec_1 = ["hello", "world"]
    message_vec_2 = []
    sk, pk = generate_key(message_vec_1)
    signature = sign(sk, encode_to_bytes(message_vec_1))
    assert verify(pk, signature, encode_to_bytes(message_vec_2))

""" Issuance protocol tests """
def test_success_issuance():
    sk, pk = generate_key(["key"] * 5)
    user_attributes = [Attribute(0, "key0", "value0"), Attribute(1, "key1", "value1"), Attribute(2, "key2", "value2")]
    issuer_attributes = [Attribute(3, "key3", "value3"), Attribute(4, "key4", "value4")]
    issue_request, t = create_issue_request(pk, user_attributes)
    blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)
    credential = obtain_credential(pk, blind_signature, t)
    attributes = [attr.to_bytes() for attr in user_attributes] + [attr.to_bytes() for attr in issuer_attributes]
    assert verify(pk, credential, attributes)

@pytest.mark.xfail(raises=AssertionError)
def test_failure_issuance_wrong_attributes():
    sk, pk = generate_key(["key"] * 5)
    user_attributes = [Attribute(0, "key0", "value0"), Attribute(1, "key1", "value1"), Attribute(2, "key2", "value2")]
    issuer_attributes = [Attribute(3, "key3", "value3"), Attribute(4, "key4", "value4")]
    issue_request, t = create_issue_request(pk, user_attributes)
    blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)
    credential = obtain_credential(pk, blind_signature, t)
    # change one attribute in user_attributes
    user_attributes = [Attribute(0, "key0", "CHANGE"), Attribute(1, "key1", "value1"), Attribute(2, "key2", "value2")]
    attributes = [attr.to_bytes() for attr in user_attributes] + [attr.to_bytes() for attr in issuer_attributes]
    assert verify(pk, credential, attributes)

@pytest.mark.xfail(raises=ZKPVerificationError)
def test_failure_issuance_wrong_zkp():
    sk, pk = generate_key(["key"] * 5)
    user_attributes = [Attribute(0, "key0", "value0"), Attribute(1, "key1", "value1"), Attribute(2, "key2", "value2")]
    issuer_attributes = [Attribute(3, "key3", "value3"), Attribute(4, "key4", "value4")]
    issue_request, t = create_issue_request(pk, user_attributes)
    # change pi
    issue_request.pi.generators.append(G1.generator() ** G1.order().random())
    issue_request.pi.s.append(G1.order().random())
    sign_issue_request(sk, pk, issue_request, issuer_attributes)

""" Showing protocol tests """    
def test_success_disclosure_proof_1():
    """ hidden_attributes = user_attributes, disclosed_attributes = issuer_attributes"""
    sk, pk = generate_key(["key"] * 2)
    user_attributes = [Attribute(0, "secret_key", "value0")]
    issuer_attributes = [Attribute(1, "rest", "true")]
    # issuance protocol
    issue_request, t = create_issue_request(pk, user_attributes)
    blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)
    credential = obtain_credential(pk, blind_signature, t)
    # showing protocol
    anonymous_credential = credential.anonymize()
    hidden_attributes = user_attributes
    disclosed_attributes = issuer_attributes
    disclosure_proof = create_disclosure_proof(pk, anonymous_credential, hidden_attributes, b"hello world")
    assert verify_disclosure_proof(pk, disclosure_proof, b"hello world", disclosed_attributes)
                    
def test_success_disclosure_proof_2():
    """ hidden_attributes = user_attributes, disclosed_attributes = []"""
    sk, pk = generate_key(["key"] * 2)
    user_attributes = [Attribute(0, "secret_key", "value0"), Attribute(1, "username", "value1")]
    issuer_attributes = []
    # issuance protocol
    issue_request, t = create_issue_request(pk, user_attributes)
    blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)
    credential = obtain_credential(pk, blind_signature, t)
    # showing protocol
    anonymous_credential = credential.anonymize()
    hidden_attributes = user_attributes
    disclosed_attributes = []
    disclosure_proof = create_disclosure_proof(pk, anonymous_credential, hidden_attributes, b"hello world")
    assert verify_disclosure_proof(pk, disclosure_proof, b"hello world", disclosed_attributes)              

def test_success_disclosure_proof_3():
    """ hidden_attributes = [], disclosed_attributes = issuer_attributes"""
    sk, pk = generate_key(["key"] * 2)
    user_attributes = []
    issuer_attributes = [Attribute(0, "key0", "value0"), Attribute(1, "key1", "value1")]
    # issuance protocol
    issue_request, t = create_issue_request(pk, user_attributes)
    blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)
    credential = obtain_credential(pk, blind_signature, t)
    # showing protocol
    anonymous_credential = credential.anonymize()
    hidden_attributes = []
    disclosed_attributes = issuer_attributes
    disclosure_proof = create_disclosure_proof(pk, anonymous_credential, hidden_attributes, b"hello world")
    assert verify_disclosure_proof(pk, disclosure_proof, b"hello world", disclosed_attributes)
    
def test_success_disclosure_proof_custom_disclosure_1():
    sk, pk = generate_key(["key"] * 3)
    user_attributes = [Attribute(0, "username", "value0")]
    issuer_attributes = [Attribute(1, "rest", "true"), Attribute(2, "dojo", "true")]
    # issuance protocol
    issue_request, t = create_issue_request(pk, user_attributes)
    blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)
    credential = obtain_credential(pk, blind_signature, t)
    # showing protocol
    anonymous_credential = credential.anonymize()
    hidden_attributes = [Attribute(0, "username", "value0"), Attribute(1, "rest", "true")]
    disclosed_attributes = [Attribute(2, "dojo", "true")]
    disclosure_proof = create_disclosure_proof(pk, anonymous_credential, hidden_attributes, b"hello world")
    assert verify_disclosure_proof(pk, disclosure_proof, b"hello world", disclosed_attributes)

def test_success_disclosure_proof_custom_disclosure_2():
    sk, pk = generate_key(["key"] * 5)
    user_attributes = [Attribute(0, "secret_key", "value0"), Attribute(1, "username", "value1")]
    issuer_attributes = [Attribute(2, "rest", "true"), Attribute(3, "dojo", "true"), Attribute(4, "bar", "false")]
    # issuance protocol
    issue_request, t = create_issue_request(pk, user_attributes)
    blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)
    credential = obtain_credential(pk, blind_signature, t)
    # showing protocol
    anonymous_credential = credential.anonymize()
    hidden_attributes = [Attribute(0, "secret_key", "value0"), Attribute(1, "username", "value1"), Attribute(2, "rest", "true")]
    disclosed_attributes = [Attribute(3, "dojo", "true"), Attribute(4, "bar", "false")]
    disclosure_proof = create_disclosure_proof(pk, anonymous_credential, hidden_attributes, b"hello world")
    assert verify_disclosure_proof(pk, disclosure_proof, b"hello world", disclosed_attributes)      

def test_success_disclosure_proof_custom_disclosure_3():
    sk, pk = generate_key(["key"] * 5)
    user_attributes = [Attribute(0, "secret_key", "value0"), Attribute(1, "username", "value1")]
    issuer_attributes = [Attribute(2, "rest", "true"), Attribute(3, "dojo", "true"), Attribute(4, "bar", "false")]
    # issuance protocol
    issue_request, t = create_issue_request(pk, user_attributes)
    blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)
    credential = obtain_credential(pk, blind_signature, t)
    # showing protocol
    anonymous_credential = credential.anonymize()
    hidden_attributes = [Attribute(0, "secret_key", "value0"), Attribute(1, "username", "value1"), Attribute(2, "rest", "true"), Attribute(3, "dojo", "true"), Attribute(4, "bar", "false")]
    disclosed_attributes = []
    disclosure_proof = create_disclosure_proof(pk, anonymous_credential, hidden_attributes, b"hello world")
    assert verify_disclosure_proof(pk, disclosure_proof, b"hello world", disclosed_attributes) 

def test_success_disclosure_proof_custom_disclosure_4():
    sk, pk = generate_key(["key"] * 5)
    user_attributes = [Attribute(0, "secret_key", "value0"), Attribute(1, "username", "value1")]
    issuer_attributes = [Attribute(2, "rest", "true"), Attribute(3, "dojo", "true"), Attribute(4, "bar", "false")]
    # issuance protocol
    issue_request, t = create_issue_request(pk, user_attributes)
    blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)
    credential = obtain_credential(pk, blind_signature, t)
    # showing protocol
    anonymous_credential = credential.anonymize()
    hidden_attributes = []
    disclosed_attributes = [Attribute(0, "secret_key", "value0"), Attribute(1, "username", "value1"), Attribute(2, "rest", "true"), Attribute(3, "dojo", "true"), Attribute(4, "bar", "false")]
    disclosure_proof = create_disclosure_proof(pk, anonymous_credential, hidden_attributes, b"hello world")
    assert verify_disclosure_proof(pk, disclosure_proof, b"hello world", disclosed_attributes) 

@pytest.mark.xfail(raises=AssertionError)
def test_failure_disclosure_proof_different_message():
    sk, pk = generate_key(["key"] * 5)
    user_attributes = [Attribute(0, "secret_key", "value0"), Attribute(1, "username", "value1")]
    issuer_attributes = [Attribute(2, "rest", "true"), Attribute(3, "dojo", "true"), Attribute(4, "bar", "false")]
    # issuance protocol
    issue_request, t = create_issue_request(pk, user_attributes)
    blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)
    credential = obtain_credential(pk, blind_signature, t)
    # showing protocol
    anonymous_credential = credential.anonymize()
    hidden_attributes = [Attribute(0, "secret_key", "value0"), Attribute(1, "username", "value1"), Attribute(2, "rest", "true")]
    disclosed_attributes = [Attribute(3, "dojo", "true"), Attribute(4, "bar", "false")]
    disclosure_proof = create_disclosure_proof(pk, anonymous_credential, hidden_attributes, b"hello world")
    assert verify_disclosure_proof(pk, disclosure_proof, b"hello ATOPET!", disclosed_attributes) 

@pytest.mark.xfail(raises=AssertionError)
def test_failure_disclosure_proof_different_attribute():
    sk, pk = generate_key(["key"] * 3)
    user_attributes = [Attribute(0, "secret_key", "value0"), Attribute(1, "username", "value1")]
    issuer_attributes = [Attribute(2, "rest", "false")]
    # issuance protocol
    issue_request, t = create_issue_request(pk, user_attributes)
    blind_signature = sign_issue_request(sk, pk, issue_request, issuer_attributes)
    credential = obtain_credential(pk, blind_signature, t)
    # showing protocol
    anonymous_credential = credential.anonymize()
    hidden_attributes = [Attribute(0, "secret_key", "value0"), Attribute(1, "username", "value1")]
    # change false to true
    disclosed_attributes = [Attribute(2, "rest", "true")]
    disclosure_proof = create_disclosure_proof(pk, anonymous_credential, hidden_attributes, b"hello world")
    assert verify_disclosure_proof(pk, disclosure_proof, b"hello world", disclosed_attributes)  