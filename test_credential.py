import pytest

from credential import generate_key, sign, verify

def test_scheme_1():
    message_vec = [b"hello", b"world"]
    sk, pk = generate_key(message_vec)
    signature = sign(sk, message_vec)
    assert verify(pk, signature, message_vec)

def test_scheme_2():
    message_vec_1 = [b"hello", b"world"]
    message_vec_2 = [b"hello", b"world", b"!"]
    sk, pk = generate_key(message_vec_1)
    signature = sign(sk, message_vec_1)
    assert verify(pk, signature, message_vec_2)

def test_scheme_3():
    message_vec = []
    sk, pk = generate_key(message_vec)
    signature = sign(sk, message_vec)
    assert verify(pk, signature, message_vec)  

