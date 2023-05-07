from serialization_utils import *
from credential_utils import Attribute


def test_serialization():
    obj = "test"
    res = serialize(obj).encode()
    assert deserialize(res.decode()) == obj
    
def test_serialization_with_custom_type():
    obj = Attribute(1,"key","value")
    res = serialize(obj)
    obj1: Attribute = deserialize(res)
    assert obj.index == obj1.index and obj.key == obj1.key and obj.value == obj1.value
