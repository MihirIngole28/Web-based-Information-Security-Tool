from flask import Flask, render_template, request, jsonify
import pyodbc
import base64
from utils import main, dhkeygeneration, rsaencryption, hashcheck, aesencryption
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import os, io

#References: https://docs.python.org/3/library/hashlib.html

app = Flask(__name__)

app=Flask(__name__,template_folder='templates') #CHANGE WHEN ADDING FRONTPAGE

#CONNECTION STRING  SQL 
#driver= '{ODBC Driver 13 for SQL Server}'
driver= '{ODBC Driver 17 for SQL Server}'
server = 'tcp:mihirsteganographysqlserver.database.windows.net,1433'
database = 'MihirSteganographySQLDB'
username = 'myingole28'
password = 'TestPassword123'
#conn = pyodbc.connect('DRIVER={SQL Server};SERVER='+server+';DATABASE='+database+';UID='+username+';PWD='+ password)
conn = pyodbc.connect('DRIVER='+driver+';SERVER='+server+';DATABASE='+database+';UID='+username+';PWD='+ password+';')
cursor = conn.cursor() #cursor 
cursor.execute('''select * from Users''')
rows = cursor.fetchall()

current_username=None

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/login')
def login():
   return render_template('login.html')

@app.route('/login/userlogin',methods=['POST'])
def userlogin():
        if request.method=='POST':
            details=request.form.get
            username=details("username")
            password=details("password")
            password = hashlib.sha256(password.encode()).hexdigest()
            global current_username
            current_username = username
            cursor.execute('''Select username from users where username = ? and password =? ;''',username,password)
            if cursor.rowcount == 0:
                  return render_template('login.html')
            else:
                  return render_template('user.html')


@app.route('/login/userlogin/user')
def user():
        return render_template('user.html',username = current_username)

@app.route('/login/userlogin/user/steganography')
def steganography():
        return render_template('steganography.html')

@app.route('/login/userlogin/user/encryption')
def encryption():
    return render_template('encryption.html')


@app.route('/login/userlogin/user/encryption/encryptioninput',methods=['POST'])
def encryptioninput():
        if request.method=='POST':
            details=request.form.get
            try:
               message_data=request.files["messageFile"].read()
            except:
               return "Fetching files was not successful"
            

            message_len = len(message_data)
            
            encryptionType=details("encryptionType")
            blockMode=details("blockMode")
            senderUsername=details("senderUsername")
            receiverUsername=details("receiverUsername")

            #message_data=base64.b64encode(message_data).decode('utf-8')

            if encryptionType == 'AES':
                iv = os.urandom(16)
                cursor.execute("SELECT dh_symmetric_key FROM Users WHERE username = ?",senderUsername)
                dh_sender_key_private_str = cursor.fetchone()[0]
                dh_sender_key_private = base64.b64decode(dh_sender_key_private_str)
                dh_sender_key_public = dhkeygeneration.getDHPublicKeysInBytes(dh_sender_key_private)
                
                cursor.execute("SELECT dh_symmetric_key FROM Users WHERE username = ?",receiverUsername)
                dh_receiver_key_private_str = cursor.fetchone()[0]
                dh_receiver_key_private = base64.b64decode(dh_receiver_key_private_str)
                dh_receiver_key_public = dhkeygeneration.getDHPublicKeysInBytes(dh_receiver_key_private)

                public_key = dh_receiver_key_public
                
                encryptionKey = dhkeygeneration.sharedDHKey(dh_sender_key_private, dh_receiver_key_public)[:32]
                encryptedBytes = aesencryption.AESEncryption(encryptionKey, message_data, iv, mode=blockMode)

                decryptionKey = dhkeygeneration.sharedDHKey(dh_receiver_key_private, dh_sender_key_public)[:32]
                decryptedBytes = aesencryption.AESDecryption(decryptionKey,encryptedBytes, iv, mode=blockMode)[:message_len]

                print('=============================Message_data=====================================================')
                print(message_data)
                print('===================================encryptedBytes===============================================')
                print(encryptedBytes)
                print('===================================decryptedBytes===============================================')
                print(decryptedBytes)

            else:

               cursor.execute("SELECT rsa_asymmetric_key FROM Users WHERE username = ?",receiverUsername)
               rsa_receiver_private_key_str = cursor.fetchone()[0]
               rsa_receiver_private_key = base64.b64decode(rsa_receiver_private_key_str)
               
               rsa_receiver_public_key = rsaencryption.getRSAPublicKeysInBytes(rsa_receiver_private_key)

               public_key = rsa_receiver_public_key

               message_data = bytes(message_data, encoding='utf8') if not isinstance(message_data, bytes) else message_data
               encryptedBytes  = rsaencryption.RSAEncryption(rsa_receiver_public_key, message_bytes)
               encryptedData  = str(base64.b64encode(encryptedBytes), encoding='utf-8')

               decryptedBytes = rsaencryption.RSADecryption(rsa_receiver_private_key, encryptedData)
               decryptedData = str(decryptedBytes, encoding='utf8')

               print(decryptedData)
               print('=============================Message_data=====================================================')
               print(message_data)
               print('===================================encryptedBytes===============================================')
               print(encryptedBytes)
               print('===================================decryptedBytes===============================================')
               print(decryptedBytes)

            return render_template('encryption_output.html',
                                   public_key_bytes=public_key,
                                   encrypted_file_bytes=encryptedBytes,
                                   decrypted_file_bytes=decryptedBytes,
                                   hash_original=hashcheck.generateHash(message_data), 
                                   hash_decrypted=hashcheck.generateHash(decryptedBytes),
                                   hash_comparision=hashcheck.compareHash(message_data, decryptedBytes))
        

@app.route('/login/userlogin/user/steganography/inputdetails',methods=['POST'])
def inputdetails():
        if request.method=='POST':
            details=request.form.get
            try:
               message_data=request.files["message_file"].read()
               carrier_data=request.files["plaintext_file"].read()
            except:
               return "Fetching files was not successful"
            starting_bit=details("starting_bit")
            message_format=details("message_format")
            carrier_format=details("carrier_format")
            mode=details("mode")
            if mode == 'fixed':
               length_of_replacement=details("length_of_replacement")
            else:
               length_of_replacement=None
            
            (hidden_data, retrieved_data) = main.core(carrier_data, message_data, starting_bit, length_of_replacement, mode)

            message_data=base64.b64encode(message_data).decode('utf-8')
            carrier_data=base64.b64encode(carrier_data).decode('utf-8')
            hidden_data=base64.b64encode(hidden_data).decode('utf-8')
            retrieved_data=base64.b64encode(retrieved_data).decode('utf-8')
            
            cursor.execute('''Insert into Steganography (username, message_file, carrier_file, starting_bit, mode, length, hidden_data, retrieved_data, carrier_format, message_format) values ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',current_username,message_data,carrier_data,starting_bit,mode,length_of_replacement,hidden_data,retrieved_data,carrier_format,message_format)
            cursor.commit()

            cursor.execute('SELECT username, message_file, carrier_file, hidden_data, retrieved_data, carrier_format, message_format FROM Steganography')
            files = cursor.fetchall()

            files_list = []
            for username, message_file, carrier_file, hidden_data, retrieved_data, carrier_format, message_format in files:
               files_list.append({'name':username+': message_file'+message_format[-4:], 'data': message_file, 'type': message_format[-4:]})
               files_list.append({'name':username+': carrier_file'+carrier_format[-4:], 'data': carrier_file, 'type': carrier_format[-4:]})
               files_list.append({'name':username+': hidden_data'+carrier_format[-4:], 'data': hidden_data, 'type': carrier_format[-4:]})
               files_list.append({'name':username+': retrieved_data'+message_format[-4:], 'data': retrieved_data, 'type': message_format[-4:]})
            return render_template('gallery.html', files=files_list)

@app.route('/login/userlogin/user/gallery')
def gallery():
    cursor.execute('SELECT username, message_file, carrier_file, hidden_data, retrieved_data, carrier_format, message_format FROM Steganography')
    files = cursor.fetchall()

    files_list = []
    for username, message_file, carrier_file, hidden_data, retrieved_data, carrier_format, message_format in files:
        files_list.append({'name':username+': message_file'+message_format[-4:], 'data': message_file, 'type': message_format[-4:]})
        files_list.append({'name':username+': carrier_file'+carrier_format[-4:], 'data': carrier_file, 'type': carrier_format[-4:]})
        files_list.append({'name':username+': hidden_data'+carrier_format[-4:], 'data': hidden_data, 'type': carrier_format[-4:]})
        files_list.append({'name':username+': retrieved_data'+message_format[-4:], 'data': retrieved_data, 'type': message_format[-4:]})
    return render_template('gallery.html', files=files_list)

@app.route('/login/register')
def register():
   return render_template('register.html')

@app.route('/login/register/userdetails',methods=['POST'])
def userdetails():
   if request.method=='POST':
      details=request.form.get
      firstname=details("first_name")
      lastname=details("last_name")
      username=details("username")
      password=details("password")
      confirmpassword=details("confirm_password")

      cursor.execute("SELECT operation_id, dh_symmetric_key, rsa_asymmetric_key FROM keys WHERE used = 0")
      result = cursor.fetchone()
           
      if result:
         operation_id, dh_symmetric_key, rsa_asymmetric_key = result
         #dh_symmetric_key_value = base64.b64decode(dh_symmetric_key_value.encode('utf-8'))
         #rsa_asymmetric_key_value = base64.b64decode(rsa_asymmetric_key_value.encode('utf-8'))
         cursor.execute("UPDATE keys SET used = 1 WHERE operation_id = ?", (operation_id))

      if password == confirmpassword:
         password = hashlib.sha256(password.encode()).hexdigest()
         cursor.execute('''Insert into Users (username, password, first_name, last_name, dh_symmetric_key, rsa_asymmetric_key) values (?, ?, ?, ?, ?, ?)''',username,password,firstname,lastname, dh_symmetric_key, rsa_asymmetric_key)
         cursor.commit()
         return render_template('login.html')
      else:
         return render_template('register.html')
    

@app.route('/login/guest')
def guest():
   return render_template('guest.html')


@app.route('/login/guest/guestdetails',methods=['POST'])
def guestdetails():
   if request.method=='POST':
      details=request.form.get
      firstname=details("first_name")
      lastname=details("last_name")
      cursor.execute('''Insert into Guest (first_name, last_name) values (?, ?)''',firstname,lastname)
      cursor.commit()
      cursor.execute('SELECT username, message_file, carrier_file, hidden_data, retrieved_data, carrier_format, message_format FROM Steganography')
      files = cursor.fetchall()

      files_list = []
      for username, message_file, carrier_file, hidden_data, retrieved_data, carrier_format, message_format in files:
         files_list.append({'name':username+': message_file'+message_format[-4:], 'data': message_file, 'type': message_format[-4:]})
         files_list.append({'name':username+': carrier_file'+carrier_format[-4:], 'data': carrier_file, 'type': carrier_format[-4:]})
         files_list.append({'name':username+': hidden_data'+carrier_format[-4:], 'data': hidden_data, 'type': carrier_format[-4:]})
         files_list.append({'name':username+': retrieved_data'+message_format[-4:], 'data': retrieved_data, 'type': message_format[-4:]})
   return render_template('gallery.html', files=files_list)

if __name__ == '__main__':
    app.run(debug=True)