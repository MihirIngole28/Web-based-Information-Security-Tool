#References: https://medium.com/@Raulgzm/rsa-with-cryptography-python-library-462b26ce4120
#https://pypi.org/project/cryptography/

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import base64

def getRSAPublicKeysInBytes(private_key_bytes):

    public_key = rsa_private_key_deserialization(private_key_bytes).public_key()
    
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return public_key_bytes

def RSAEncryption(receivers_public_key, data):
    return rsa_public_key_deserialization(receivers_public_key).encrypt(
      data,
      padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
      )
    )

def rsa_private_key_deserialization(key):
    private_key = serialization.load_pem_private_key(
        key,
        password=None,  # No password as the private key is not encrypted
        backend=default_backend()
    )
    return private_key

def rsa_public_key_deserialization(key):
    public_key = serialization.load_pem_public_key(
        key,
        backend=default_backend()
    )
    return public_key
    
def RSADecryption(private_key, cipher_text):
    ciphertext_decoded = base64.b64decode(cipher_text) if not isinstance(cipher_text, bytes) else cipher_text
    return rsa_private_key_deserialization(private_key).decrypt(
        ciphertext_decoded,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )



def getRSAKeysInBytes():

    private_key = rsa.generate_private_key(
     public_exponent=65537,
     key_size=2048,
     backend=default_backend()
    )

    public_key = private_key.public_key()
    
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key_bytes, public_key_bytes