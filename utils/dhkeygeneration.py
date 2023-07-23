#References: https://stackoverflow.com/questions/43886464/cryptography-python-diffie-hellman-key-exchange-implementation
#https://www.geeksforgeeks.org/implementation-diffie-hellman-algorithm/

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import os
import random

parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())



def getDHKeysInBytes(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key_bytes, public_key_bytes

def getDHPublicKeysInBytes(private_key_bytes):
    private_key = serialization.load_der_private_key(
        private_key_bytes, password=None, backend=default_backend()
    )
    public_key = private_key.public_key()
    
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_bytes

def sharedDHKey(senderPrivateKeyBytes, receiverPublicKeyBytes):
    senderPrivateKey = serialization.load_der_private_key(
        senderPrivateKeyBytes, password=None, backend=default_backend()
    )
    
    receiverPublicKey = serialization.load_der_public_key(
        receiverPublicKeyBytes, backend=default_backend()
    )
    
    return senderPrivateKey.exchange(receiverPublicKey)