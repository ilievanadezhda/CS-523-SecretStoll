from typing import List

from credential_utils import PublicKey

import string
import random

# Constants
ATTR_SECRET_KEY = "secret_key"
ATTR_USERNAME = "username"
CLIENT_SK_LENGTH = 128


def get_all_attribute_keys(pk: PublicKey) -> List[str]:
    """ Returns keys for all possible attributes """
    return pk.attr_indices_dict.keys()


def get_secret_key(length: int):
    """ Generate random secret key for the client """
    random_source = string.ascii_letters + string.digits + string.punctuation
    sk = ''
    for _ in range(length):
        sk += random.choice(random_source)

    return sk
