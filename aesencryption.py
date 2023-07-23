#References: https://stackoverflow.com/questions/25261647/python-aes-encryption-without-extra-module
#https://pypi.org/project/cryptography/

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

def AESEncryption(key, data, iv, mode="CBC"):
    '''Only excepts CBC, OFB and CFB modes'''
    
    if mode == 'CBC':
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    elif mode == 'OFB':
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
    elif mode == 'CFB':
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    else:
        raise ValueError('Invalid Mode.')
        
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_message_data = padder.update(data) + padder.finalize()

    return encryptor.update(padded_message_data) + encryptor.finalize()

def AESDecryption(key,cipher_text, iv, mode='CBC'):  
    
    if mode == 'CBC':
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    elif mode == 'OFB':
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=default_backend())
    elif mode == 'CFB':
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    else:
        raise ValueError('Invalid Mode.')
    decryptor = cipher.decryptor()
    decrypted_file = decryptor.update(cipher_text) + decryptor.finalize()
    return decrypted_file