#References: https://medium.com/@Raulgzm/rsa-with-cryptography-python-library-462b26ce4120

import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def generateHash(data):
    sha2_algorithm = hashes.SHA256()
    hasher = hashes.Hash(sha2_algorithm, backend=default_backend())
    hasher.update(data)
    message_hash = hasher.finalize()
    return message_hash

def compareHash(original, decrypted):
    return generateHash(original) == generateHash(decrypted)