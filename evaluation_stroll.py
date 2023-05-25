from _collections_abc import Callable
from _operator import sub
from os import path, remove
import pytest
from timeit import default_timer as timer
from typing import List, Any, Tuple

from credential_utils import PublicKey
from serialization_utils import serialize_to_bytes, from_bytes_deserialize
from stroll import Server, Client
from stroll_utils import write_to_file
from statistics import mean

EVALUATION_RESULTS_FILENAME = "evaluation.csv"
NUM_EXECUTIONS_SD = 30

""" Evaluation utilities """


def measure_communication_cost(items: List[Any]) -> float:
    """ Utility for measuring communication cost """
    """ Returns result in kilobytes """
    total_bytes = 0
    for item in items:
        total_bytes += len(serialize_to_bytes(item))
    return convert_bytes_to_kb(total_bytes)


def convert_bytes_to_kb(num_bytes: int) -> float:
    """ Utility for converting bytes to kilobytes """
    return num_bytes / float(1024)


def remove_results_file():
    """ Remove the file with the results programmatically """
    if path.exists(EVALUATION_RESULTS_FILENAME):
        remove(EVALUATION_RESULTS_FILENAME)

        
def write_result(result_line: str):
    write_to_file("{}\n".format(result_line), EVALUATION_RESULTS_FILENAME, "at")


""" Evaluation test """


@pytest.mark.parametrize("num_attributes,write_header", [(2, True), (5, False), (10, False), (50, False), (100, False), (200, False), (500, False), (1000, False)])
def test_evaluation(num_attributes, write_header):
    """ The integration test for the evaluation """
    
    if write_header:
        write_result("num_attributes,generation_comp,generation_comm,issuance_comp,issuance_comm,showing_comp,showing_comm,verification_comp,verification_comm")
    
    for _ in range(NUM_EXECUTIONS_SD):
        ### KEY GENERATION ###
        # setup
        server = Server()
        attributes = ["sub_{}".format(str(i)) for i in range(num_attributes - 2)]
        # doesn't need to be added when running the client and the server, as the server
        # adds it automatically
        attributes.append("username")
    
        # operation
        start_generation = timer()
        result = server.generate_ca(attributes)
        generation_comp_cost = timer() - start_generation
    
        # NO COMMUNICATION COST, HAPPENS ON SERVER SIDE ONLY
        generation_comm_cost = measure_communication_cost([])
        print("Key generation: {}s,{}kb".format(generation_comp_cost, generation_comm_cost))
    
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
    
        issuance_comm_cost = measure_communication_cost([issue_request, subscriptions, signature])
        print("Issuance: {}s,{}kb".format(issuance_comp_cost, issuance_comm_cost))
    
        ### SHOWING CREDENTIAL ###
        # setup
        message = b"message"
        # assuming we request all subscribed location types
        types = subscriptions
    
        # operation
        start_disclosure = timer()
        disclosure_proof = client.sign_request(result[1], credential, message, types)
        disclosure_comp_cost = timer() - start_disclosure
    
        disclosure_comm_cost = measure_communication_cost([message, types, disclosure_proof])
        print("Showing: {}s,{}kb".format(disclosure_comp_cost, disclosure_comm_cost))
    
        ### VERIFYING CREDENTIAL ###
        # operation
        start_verification = timer()
        _ = server.check_request_signature(result[1], message, types, disclosure_proof)
        verification_comp_cost = timer() - start_verification

        # NO COMMUNICATION COST, HAPPENS ON SERVER SIDE ONLY
        verification_comm_cost = measure_communication_cost([])
        print("Verifying: {}s,{}kb".format(verification_comp_cost, verification_comm_cost))
    
        write_result("{},{},{},{},{},{},{},{},{}".format(str(num_attributes), str(generation_comp_cost), str(generation_comm_cost), str(issuance_comp_cost), str(issuance_comm_cost), str(disclosure_comp_cost), str(disclosure_comm_cost), str(verification_comp_cost), str(verification_comm_cost)))


""" Utility tests """


def test_delete_results_file():
    remove_results_file()
