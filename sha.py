import hashlib
def generate_sha_hash(file_name):

    with open(file_name, "r") as input_file:
        data = input_file.read()
    txt = data.encode("utf-8")

    hashed_password = hashlib.sha256(txt).hexdigest()
    return str(hashed_password)