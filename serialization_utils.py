from serialization import jsonpickle


# TODO: Check if this is the right way to do it
def serialize_to_bytes(obj):
    return jsonpickle.encode(obj).encode()

# TODO: Check if this is the right way to do it
def from_bytes_deserialize(obj):
    return jsonpickle.decode(obj.decode())
