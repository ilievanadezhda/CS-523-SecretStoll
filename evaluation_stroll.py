from _collections_abc import Callable
from _operator import sub
from timeit import default_timer as timer
from typing import List, Any, Tuple

from serialization_utils import serialize_to_bytes, from_bytes_deserialize
from stroll import Server, Client
from credential_utils import PublicKey

""" Evaluation utilities """
def measure_communication_cost(items: List[Any]) -> int:
    """ Utility for measuring communication cost """
    total_bytes = 0
    for item in items:
        total_bytes += len(serialize_to_bytes(item))
    return total_bytes


def measure_computation_cost(process: Callable[..., Any], args: Any) -> Tuple[Any, float]:
    """ Utility for measuring computation cost """
    start = timer()
    response = process(args)
    end = timer()
    return response, end - start

""" Evaluation tests """
def test_evaluation():
    """ The integration test for the evaluation, work in progress """
    
    ### KEY GENERATION ###
    # configuration
    num_attributes = 5
    
    # setup
    server = Server()
    attributes = ["sub_{}".format(str(i)) for i in range(num_attributes - 2)]
    attributes.append("secret_key")
    # doesn't need to be added when running the client and the server, as the server
    # adds it automatically
    attributes.append("username")
    
    # operation
    start_generation = timer()
    result = server.generate_ca(attributes)
    generation_comp_cost = timer() - start_generation
    # todo: check if other operations can be simplified like e.g.:
    # result, computation_cost = measure_computation_cost(server.generate_ca, attributes)
    
    generation_comm_cost = measure_communication_cost([attributes])
    print("Key generation: {}s,{}bytes".format(generation_comp_cost, generation_comm_cost))
    
    ### ISSUANCE (commitment, signing, unblinding) ###
    # setup
    client = Client()
    username = "user1"
    subscriptions = attributes[:num_attributes - 2]

    # operation
    start_issuance = timer()
    issue_request, state = client.prepare_registration(result[1], username, subscriptions)
    signature = server.process_registration(result[0], result[1], issue_request, username, subscriptions)
    credential = client.process_registration_response(result[1], signature, state)
    issuance_comp_cost = timer() - start_issuance
    
    # todo: check if we should we count the public key of the server as part of the communication cost?
    issuance_comm_cost = measure_communication_cost([issue_request, subscriptions, signature])
    print("Issuance: {}s,{}bytes".format(issuance_comp_cost, issuance_comm_cost))
    
    # todo: finish up - add measurements
    ### SHOWING CREDENTIAL ###
    # setup
    message = b"message"
    # assuming we request all subscribed location types
    types = subscriptions
    
    disclosure_proof = client.sign_request(result[1], credential, message, types)
    
    ### VERIFYING CREDENTIAL ###
    verification_result = server.check_request_signature(result[1], message, types, disclosure_proof)