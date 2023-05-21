from typing import List

from credential_utils import PublicKey

import string
import random
from serialization_utils import serialize, deserialize

# Constants
ATTR_SECRET_KEY = "secret_key"
ATTR_USERNAME = "username"
CLIENT_SK_LENGTH = 128

# Local persistence file names
USERNAME_FILE = "username.txt"
SECRET_KEY_FILE = "secret_key.txt"
SUBSCRIPTIONS_FILE = "subscriptions.txt"


def get_all_attribute_keys(pk: PublicKey) -> List[str]:
    """ Returns keys for all possible attributes """
    return pk.attr_indices_dict.keys()


def get_random_secret_key(length: int) -> str:
    """ Generates random secret key for the client """
    random_source = string.ascii_letters + string.digits + string.punctuation
    sk = ''
    for _ in range(length):
        sk += random.choice(random_source)

    return sk


def write_to_file(content: str, file_name: str, strategy: str = "wt"):
    """ Writes the content to the provided file name.
    File is created if not existent and re-written each time """
    with open(file_name, strategy) as f:
        f.write(content)


def read_file_content(file_name: str):
    """ Reads file and returns read content """
    with open(file_name, "r") as f:
        return f.read()


def persist_username(username: str):
    """ Writes the username to local file """
    write_to_file(username, USERNAME_FILE)

        
def read_username() -> str:
    """ Reads the username from the local file """
    return read_file_content(USERNAME_FILE)


def persist_secret_key():
    """ Generates random secret key and writes it to local file """
    write_to_file(get_random_secret_key(CLIENT_SK_LENGTH), SECRET_KEY_FILE)

        
def read_secret_key() -> str:
    """ Reads the secret key from the local file """
    return read_file_content(SECRET_KEY_FILE)


def persist_subscriptions(subscriptions: List[str]):
    """ Writes the subscriptions to local file """
    write_to_file(serialize(subscriptions), SUBSCRIPTIONS_FILE)

        
def read_subscriptions() -> List[str]:
    """ Reads the subscriptions from the local file """
    return deserialize(read_file_content(SUBSCRIPTIONS_FILE))
