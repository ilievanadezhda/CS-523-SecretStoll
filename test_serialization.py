from serialization_utils import *


def test_serialization():
    obj = "test"
    res = serialize(obj).encode()
    assert deserialize(res.decode()) == obj
