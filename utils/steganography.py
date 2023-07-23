import os

def bytesToBits(Bytes):
    res = "".join(f'{byte:08b}' for byte in Bytes)
    return res

def bitsToBytes(bits):
    res = bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8))
    return res


def hiding_message(carrier, message, start_bit, length, mode='fixed'):
    carrier_data = bytesToBits(carrier)
    message_data = bytesToBits(message)

    if mode=='fixed':
        length_vals = [length]
    elif mode=='variable':
        length_vals = [8, 16, 28]
    else:
        raise ValueError('Invalid mode. Please choose either \'fixed\' or \'variable\'.')

    carrier_index = start_bit
    message_index = 0
    
    length_val = 0
    for i in range(len(message_data)):
        if carrier_index >= len(carrier_data) and message_index >= len(message_data):
            break
        carrier_data = carrier_data[:carrier_index] + message_data[message_index] + carrier_data[carrier_index+1:]
        carrier_index += length_vals[length_val]
        message_index += 1
        length_val = (length_val + 1) % len(length_vals)



    return bitsToBytes(carrier_data)


def retrieve_message(carrier, message_length, start_bit, length, mode='fixed'):
    carrier_data = bytesToBits(carrier)

    if mode=='fixed':
        length_vals = [length]
    elif mode =='variable':
        length_vals = [8, 16, 28]
    else:
        raise ValueError('Invalid mode. Please choose either \'fixed\' or \'variable\'.')

    carrier_index = start_bit
    message = ''

    length_val = 0
    for i in range(message_length * 8):
        if carrier_index >= len(carrier_data):
            break
        message += carrier_data[carrier_index]
        carrier_index += length_vals[length_val]
        length_val = (length_val+1) % len(length_vals)

    return bitsToBytes(message)




    
