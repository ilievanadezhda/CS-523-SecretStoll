import jsonpickle


def serialize(obj):
    return jsonpickle.encode(obj)


def deserialize(obj):
    return jsonpickle.decode(obj)
