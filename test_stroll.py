import pytest

from stroll import *

""" Test generate_ca() """


def test_generate_ca_1():
    subscriptions = ["restaurant", "bar", "dojo", "username", "secret_key"]
    server = Server()
    sk, pk = server.generate_ca(subscriptions)
    assert sk is not None and pk is not None


def test_generate_ca_2():
    subscriptions = ["restaurant", "bar", "dojo", "username", "secret_key"]
    server = Server()
    sk, pk = server.generate_ca(subscriptions)
    assert isinstance(sk, bytes) and isinstance(pk, bytes)


""" Registration tests """


def test_success_registration():
    # setup
    server = Server()
    client = Client()
    # all subscriptions supported by the server + username
    subscriptions = ["restaurant", "bar", "dojo", "username", "secret_key"]
    # server: generate keys
    sk, pk = server.generate_ca(subscriptions)
    # subscriptions that client wants to subscribe to
    client_subscriptions = ["restaurant", "bar"]
    # client: prepare registration
    issue_request, state = client.prepare_registration(pk, "username", client_subscriptions)
    # server: process registration
    blind_signature = server.process_registration(sk, pk, issue_request, "username", client_subscriptions)
    # client: process registration response
    credential = client.process_registration_response(pk, blind_signature, state)
    # check if the credential is valid
    # recreate attribute/subscription list that was signed
    pk_deserialized = from_bytes_deserialize(pk)
    restaurant_attr = Attribute(pk_deserialized.attr_indices_dict["restaurant"], "restaurant", "true").to_bytes()
    bar_attr = Attribute(pk_deserialized.attr_indices_dict["bar"], "bar", "true").to_bytes()
    dojo_attr = Attribute(pk_deserialized.attr_indices_dict["dojo"], "dojo", "false").to_bytes()
    username_attr = Attribute(pk_deserialized.attr_indices_dict["username"], "username", "username").to_bytes()
    secret_key_attr = Attribute(pk_deserialized.attr_indices_dict["secret_key"], "secret_key", client.get_secret_key()).to_bytes()
    attributes = [restaurant_attr, bar_attr, dojo_attr, username_attr, secret_key_attr]
    assert verify(from_bytes_deserialize(pk), from_bytes_deserialize(credential), attributes)


@pytest.mark.xfail(raises=AssertionError)
def test_failure_registration_changed_attribute_value():
    # setup
    server = Server()
    client = Client()
    # all subscriptions supported by the server + username
    subscriptions = ["restaurant", "bar", "dojo", "username", "secret_key"]
    # server: generate keys
    sk, pk = server.generate_ca(subscriptions)
    # subscriptions that client wants to subscribe to
    client_subscriptions = ["restaurant"]
    # client: prepare registration
    issue_request, state = client.prepare_registration(pk, "username", client_subscriptions)
    # server: process registration
    blind_signature = server.process_registration(sk, pk, issue_request, "username", client_subscriptions)
    # client: process registration response
    credential = client.process_registration_response(pk, blind_signature, state)
    # check if the credential is valid
    # recreate attribute/subscription list that was signed
    pk_deserialized = from_bytes_deserialize(pk)
    restaurant_attr = Attribute(pk_deserialized.attr_indices_dict["restaurant"], "restaurant", "true").to_bytes()
    # the value of the attribute is changed from false to true
    bar_attr = Attribute(pk_deserialized.attr_indices_dict["bar"], "bar", "true").to_bytes()
    dojo_attr = Attribute(pk_deserialized.attr_indices_dict["dojo"], "dojo", "false").to_bytes()
    username_attr = Attribute(pk_deserialized.attr_indices_dict["username"], "username", "username").to_bytes()
    secret_key_attr = Attribute(pk_deserialized.attr_indices_dict["secret_key"], "secret_key", client.get_secret_key()).to_bytes()
    attributes = [restaurant_attr, bar_attr, dojo_attr, username_attr, secret_key_attr]
    assert verify(from_bytes_deserialize(pk), from_bytes_deserialize(credential), attributes)


""" Request tests"""


def test_success_request_1():
    # setup
    server = Server()
    client = Client()
    # REGISTRATION
    # all subscriptions supported by the server + username
    subscriptions = ["restaurant", "bar", "dojo", "username", "secret_key"]
    # server: generate keys
    sk, pk = server.generate_ca(subscriptions)
    # subscriptions that client wants to subscribe to
    client_subscriptions = ["restaurant", "bar"]
    # client: prepare registration
    issue_request, state = client.prepare_registration(pk, "username", client_subscriptions)
    # server: process registration
    blind_signature = server.process_registration(sk, pk, issue_request, "username", client_subscriptions)
    # client: process registration response
    credential = client.process_registration_response(pk, blind_signature, state)
    # REQUEST
    # client: sign request
    # message
    lat, lon = 46.5197, 6.6323
    message = f"{lat},{lon}".encode()
    # types
    types = ["restaurant"]
    # request
    message_signature = client.sign_request(pk, credential, message, types)
    # server: check request signature
    assert server.check_request_signature(pk, message, types, message_signature)


def test_success_request_2():
    # setup
    server = Server()
    client = Client()
    # REGISTRATION
    # all subscriptions supported by the server + username
    subscriptions = ["restaurant", "bar", "dojo", "username", "secret_key"]
    # server: generate keys
    sk, pk = server.generate_ca(subscriptions)
    # subscriptions that client wants to subscribe to
    client_subscriptions = ["restaurant", "bar"]
    # client: prepare registration
    issue_request, state = client.prepare_registration(pk, "username", client_subscriptions)
    # server: process registration
    blind_signature = server.process_registration(sk, pk, issue_request, "username", client_subscriptions)
    # client: process registration response
    credential = client.process_registration_response(pk, blind_signature, state)
    # REQUEST
    # client: sign request
    # message
    lat, lon = 46.5197, 6.6323
    message = f"{lat},{lon}".encode()
    # types
    types = ["restaurant", "bar"]
    # request
    message_signature = client.sign_request(pk, credential, message, types)
    # server: check request signature
    assert server.check_request_signature(pk, message, types, message_signature)


@pytest.mark.xfail(raises=AssertionError)
def test_failure_request_not_subscribed_to_type_1():
    # setup
    server = Server()
    client = Client()
    # REGISTRATION
    # all subscriptions supported by the server + username
    subscriptions = ["restaurant", "bar", "dojo", "username", "secret_key"]
    # server: generate keys
    sk, pk = server.generate_ca(subscriptions)
    # subscriptions that client wants to subscribe to
    client_subscriptions = ["restaurant", "bar"]
    # client: prepare registration
    issue_request, state = client.prepare_registration(pk, "username", client_subscriptions)
    # server: process registration
    blind_signature = server.process_registration(sk, pk, issue_request, "username", client_subscriptions)
    # client: process registration response
    credential = client.process_registration_response(pk, blind_signature, state)
    # REQUEST
    # client: sign request
    # message
    lat, lon = 46.5197, 6.6323
    message = f"{lat},{lon}".encode()
    # client is not subscribed to dojo
    types = ["dojo"]
    # request
    message_signature = client.sign_request(pk, credential, message, types)
    # server: check request signature
    assert server.check_request_signature(pk, message, types, message_signature)


@pytest.mark.xfail(raises=AssertionError)
def test_failure_request_not_subscribed_to_type_2():
    # setup
    server = Server()
    client = Client()
    # REGISTRATION
    # all subscriptions supported by the server + username
    subscriptions = ["restaurant", "bar", "dojo", "username", "secret_key"]
    # server: generate keys
    sk, pk = server.generate_ca(subscriptions)
    # subscriptions that client wants to subscribe to
    client_subscriptions = ["restaurant", "bar"]
    # client: prepare registration
    issue_request, state = client.prepare_registration(pk, "username", client_subscriptions)
    # server: process registration
    blind_signature = server.process_registration(sk, pk, issue_request, "username", client_subscriptions)
    # client: process registration response
    credential = client.process_registration_response(pk, blind_signature, state)
    # REQUEST
    # client: sign request
    # message
    lat, lon = 46.5197, 6.6323
    message = f"{lat},{lon}".encode()
    # client is not subscribed to dojo
    types = ["restaurant", "bar", "dojo"]
    # request
    message_signature = client.sign_request(pk, credential, message, types)
    # server: check request signature
    assert server.check_request_signature(pk, message, types, message_signature)


@pytest.mark.xfail(raises=AssertionError)
def test_failure_different_message():
    # setup
    server = Server()
    client = Client()
    # REGISTRATION
    # all subscriptions supported by the server + username
    subscriptions = ["restaurant", "bar", "dojo", "username", "secret_key"]
    # server: generate keys
    sk, pk = server.generate_ca(subscriptions)
    # subscriptions that client wants to subscribe to
    client_subscriptions = ["restaurant", "bar"]
    # client: prepare registration
    issue_request, state = client.prepare_registration(pk, "username", client_subscriptions)
    # server: process registration
    blind_signature = server.process_registration(sk, pk, issue_request, "username", client_subscriptions)
    # client: process registration response
    credential = client.process_registration_response(pk, blind_signature, state)
    # REQUEST
    # client: sign request
    # message
    lat, lon = 46.5197, 6.6323
    message = f"{lat},{lon}".encode()
    # client is not subscribed to dojo
    types = ["restaurant", "bar", "dojo"]
    # request
    message_signature = client.sign_request(pk, credential, message, types)
    # server: check request signature
    assert server.check_request_signature(pk, f"{46.5198},{6.6323}".encode(), types, message_signature)