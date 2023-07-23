    parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
    for _ in range(100):
      dh_symmetric_key_value, _ = dhkeygeneration.getDHKeysInBytes(parameters)
      rsa_asymmetric_key_value, _ = rsaencryption.getRSAKeysInBytes()  
      dh_symmetric_key_value = base64.b64encode(dh_symmetric_key_value).decode('utf-8')
      rsa_asymmetric_key_value = base64.b64encode(rsa_asymmetric_key_value).decode('utf-8')

      cursor.execute('''INSERT INTO keys (dh_symmetric_key, rsa_asymmetric_key, used) VALUES (?, ?, ?)''',dh_symmetric_key_value, rsa_asymmetric_key_value, 0)
      cursor.commit()