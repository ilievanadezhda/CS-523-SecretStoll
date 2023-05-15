from serialization_utils import *
from credential_utils import Attribute


def test_serialization():
    obj = "test"
    res = serialize_to_bytes(obj)
    assert from_bytes_deserialize(res) == obj
    
def test_serialization_with_custom_type():
    obj = Attribute(1,"key","value")
    res = serialize_to_bytes(obj)
    obj1: Attribute = from_bytes_deserialize(res)
    assert obj.index == obj1.index and obj.key == obj1.key and obj.value == obj1.value
