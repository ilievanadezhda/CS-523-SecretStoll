from typing import List

from credential_utils import PublicKey

# Constants
ATTR_SECRET_KEY = "secret_key"
ATTR_USERNAME = "username"


def get_all_attribute_keys(pk: PublicKey) -> List[str]:
    """ Returns keys for all possible attributes """
    return pk.attr_indices_dict.keys()
