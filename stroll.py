"""
Classes that you need to complete.
"""

from typing import Any, Dict, List, Union, Tuple

from serialization_utils import *
from credential import *
from stroll_utils import *


class Server:
    """Server"""

    def __init__(self):
        """
        Server constructor.
        """
        self.secret_key = None
        self.public_key = None

    @staticmethod
    def generate_ca(
            subscriptions: List[str]
        ) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with a attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's public information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """
        """Should be called with all possible subscriptions + secret_key attribute
        key, since username is already added in server.py """
        (sk, pk) = generate_key(subscriptions)
        return serialize_to_bytes(sk), serialize_to_bytes(pk)

    def process_registration(
            self,
            server_sk: bytes,
            server_pk: bytes,
            issuance_request: bytes,
            username: str,
            subscriptions: List[str]
        ) -> bytes:
        """ Registers a new account on the server.

        Args:
            server_sk: the server's secret key (serialized)
            issuance_request: The issuance request (serialized)
            username: username
            subscriptions: attributes


        Return:
            serialized response (the client should be able to build a
                credential with this response).
        """
        
        """ Assuming user hides (part of commitment - the private key
        and the username) and subscriptions are the requested subscriptions,
        part of issuer-defined attributes in this case.
        Server (issuer) adds all attributes for all remaining possible
        subscriptions, with value equal to false.
        We are not using the username here, as we do not want to reveal it
        at any moment.
        """
        sk: SecretKey = from_bytes_deserialize(server_sk)
        pk: PublicKey = from_bytes_deserialize(server_pk)
        issue_req: IssueRequest = from_bytes_deserialize(issuance_request)
        
        # add subscribed attributes first
        issuer_attributes = [Attribute(pk.attr_indices_dict[attr_key], attr_key, "true") for attr_key in subscriptions]
        
        # append attributes for all remaining subscriptions
        all_attr_keys = get_all_attribute_keys(pk)
        missing_subs_keys = list(filter(lambda x: x not in subscriptions and x not in [ATTR_SECRET_KEY, ATTR_USERNAME],
                                        all_attr_keys))
        
        issuer_attributes.extend([Attribute(pk.attr_indices_dict[attr_key], attr_key, "false") for attr_key in missing_subs_keys])
        
        return serialize_to_bytes(sign_issue_request(sk, pk, issue_req, issuer_attributes))

    def check_request_signature(
        self,
        server_pk: bytes,
        message: bytes,
        revealed_attributes: List[str],
        signature: bytes
        ) -> bool:
        """ Verify the signature on the location request

        Args:
            server_pk: the server's public key (serialized)
            message: The message to sign
            revealed_attributes: revealed attributes
            signature: user's authorization (serialized)

        Returns:
            whether a signature is valid
        """
        
        """ Assuming user only reveals subset of subscriptions
        for which requests service - the server checks if the
        corresponding values are equal to 'true'
        
        Assuming signature is the DisclosureProof model
        """
        pk: PublicKey = from_bytes_deserialize(server_pk)
        disclosure: DisclosureProof = from_bytes_deserialize(signature)
        attributes = [Attribute(pk.attr_indices_dict[attr_key], attr_key, "true") for attr_key in revealed_attributes]
        
        return verify_disclosure_proof(pk, disclosure, message, attributes)


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """

    def prepare_registration(
            self,
            server_pk: bytes,
            username: str,
            subscriptions: List[str]
        ) -> Tuple[bytes, State]:
        """Prepare a request to register a new account on the server.

        Args:
            server_pk: a server's public key (serialized)
            username: user's name
            subscriptions: user's subscriptions

        Return:
            A tuple containing:
                - an issuance request
                - A private state. You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """
        
        """ User commits to the secret key and the username only;
        and sends requested subscriptions - based on these the server will know
        how to populate the values for all possible subscriptions as issuer-defined
        attributes """
        
        """ User's secret key, username and subscriptions are persisted in the file system """
        persist_secret_key()
        persist_username(username)
        persist_subscriptions(subscriptions)
                
        pk: PublicKey = from_bytes_deserialize(server_pk)
        # user attributes that go into the Pedersen commitment
        # username and secret key
        comm_attributes = self.get_sk_username_attributes(pk)
        # create client's issuance request
        issue_request, t = create_issue_request(pk, comm_attributes)
        return serialize_to_bytes(issue_request), State(t)

    def process_registration_response(
            self,
            server_pk: bytes,
            server_response: bytes,
            private_state: State
        ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """
        pk: PublicKey = from_bytes_deserialize(server_pk)
        blind_signature: BlindSignature = from_bytes_deserialize(server_response)
        
        # client computes the credential - not anonymized
        return serialize_to_bytes(obtain_credential(pk, blind_signature, private_state.t))

    def sign_request(
            self,
            server_pk: bytes,
            credentials: bytes,
            message: bytes,
            types: List[str]
        ) -> bytes:
        """Signs the request with the client's credential.

        Arg:
            server_pk: a server's public key (serialized)
            credential: client's credential (serialized)
            message: message to sign
            types: which attributes should be sent along with the request?

        Returns:
            A message's signature (serialized)
        """
        
        """ The client computes anonymous credential as well as disclosure proof
        at this step 
        Assuming types to be the list of requested location types in the request """
        
        pk: PublicKey = from_bytes_deserialize(server_pk)
        credential: Signature = from_bytes_deserialize(credentials)
        anonymized_cred = credential.anonymize()
        
        # client hides everything except for the requested location types
        all_attr_keys = get_all_attribute_keys(pk)
        # collect subscription hidden attributes
        hidden_subs_keys = list(filter(lambda x: x not in types and x not in [ATTR_SECRET_KEY, ATTR_USERNAME], all_attr_keys))
        hidden_subs_attrs = [Attribute(pk.attr_indices_dict[key], key, "true" if self.is_subscribed_to_type(key) else "false") for key in hidden_subs_keys]
        # add secret key and username to hidden attributes
        hidden_subs_attrs.extend(self.get_sk_username_attributes(pk))
        return serialize_to_bytes(create_disclosure_proof(pk, anonymized_cred, hidden_subs_attrs, message))

    def is_subscribed_to_type(self, a_type: str) -> bool:
        """ Returns whether the client is subscribed to the provided type of location """
        return a_type in read_subscriptions()
    
    def get_sk_username_attributes(self, pk: PublicKey) -> List[Attribute]:
        """ Returns list of populated secret key and username attribute objects """
        return [Attribute(pk.attr_indices_dict[ATTR_SECRET_KEY], ATTR_SECRET_KEY, read_secret_key()),
                Attribute(pk.attr_indices_dict[ATTR_USERNAME], ATTR_USERNAME, read_username())]
    
    def get_secret_key(self):
        return read_secret_key()
