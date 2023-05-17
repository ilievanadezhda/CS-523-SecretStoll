from serialization import jsonpickle


def serialize(obj):
    return jsonpickle.encode(obj)


def deserialize(obj):
    return jsonpickle.decode(obj)


def serialize_to_bytes(obj):
    return serialize(obj).encode("utf-8")


def from_bytes_deserialize(obj):
    return deserialize(obj.decode("utf-8"))
