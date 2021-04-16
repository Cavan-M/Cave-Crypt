
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random


def pad(s):
    return s + (32 - len(s) % 32) * str.encode(chr(32 - len(s) % 32))



def unpad(s):
    return s[:-ord(s[len(s)-1:])]


def encrypt_file(file_name, password):
    with open(file_name, "rb") as input_file:
        raw_data = pad(input_file.read())
    my_password = password.encode("utf-8")

    my_output_file = file_name + "_encrypted" + ".aes"

    hashed_password = hashlib.sha256(my_password).digest()

    iv = Random.new().read( AES.block_size )

    cipher = AES.new( hashed_password, AES.MODE_CBC, iv )

    with open(my_output_file,"wb") as output_file:

        output_file.write(base64.b64encode( iv + cipher.encrypt(raw_data)))

    my_password = ''

    hashed_password = ''

    return my_output_file



def decrypt_file(encrypted_file, password):

    with open(encrypted_file,"rb") as encrypted_file:

        encrypted_data = encrypted_file.read()

    encrypted_data = base64.b64decode(encrypted_data)

    iv = encrypted_data[:16]

    my_password = password.encode("utf-8")

    hashed_password = hashlib.sha256(my_password).digest()

    cipher = AES.new(hashed_password, AES.MODE_CBC, iv )

    decrypted_data = unpad(cipher.decrypt( encrypted_data[16:] ))

    my_password = ''
    hashed_password = ''

    return decrypted_data

