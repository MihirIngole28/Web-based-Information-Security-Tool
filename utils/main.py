import steganography
import dhkeygeneration
import hashcheck
import aesencryption
import rsaencryption

def core(carrier_data, message_data, start_bit, length, mode):
    if len(message_data) > len(carrier_data):
        raise ValueError('Message cannot be bigger than carrier in length.')

    start_bit = int((1- len(message_data)/len(carrier_data)) * len(carrier_data) - 100)
    length = 16

    hidden_data = steganography.hiding_message(carrier_data, message_data, start_bit, length, mode='fixed')

    message_length = len(message_data)

    retrieved_message = steganography.retrieve_message(hidden_data, message_length, start_bit, length, mode='fixed')

    return (hidden_data, retrieved_message)




if __name__=="__main__":
    prA, puA = getDHKeysInBytes(parameters)
    prB, puB = getDHKeysInBytes(parameters)
    key = sharedDHKey(prA, puB)[:32]
    iv = os.urandom(16)

    message_file = 'message.txt'
    with open(message_file, 'rb') as f:
        message_data = f.read()

    print(message_data)

    print(AESDecryption(cipher_text = AESEncryption(key, message_data, mode="CBC"), iv=iv, mode='CBC'))

    mariaPrv, mariaPub = getRSAKeysInBytes()
    johnPrv, johnPub = getRSAKeysInBytes()

    message = b'the code must be like a piece of music'
    message_bytes = bytes(message, encoding='utf8') if not isinstance(message, bytes) else message
    ciphertext  = RSAEncryption(johnPub, message_bytes)
    ciphertext  = str(base64.b64encode(ciphertext), encoding='utf-8')

    plain_text = RSADecryption(johnPrv, ciphertext)
    plain_text_str = str(plain_text, encoding='utf8')

    print(plain_text_str)

    compareHash(message_bytes, plain_text)