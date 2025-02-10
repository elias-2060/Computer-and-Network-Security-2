import os
from mitmproxy import http
import json
import string, random
from datetime import datetime
from .authentication import mac as mac_file
from .encryption import aes, salsa, rsa


def example_function():
    pass


# DO NOT CHANGE THIS FUNCTION DEFINITION (except for the return statement/type)
def read_config_client():
    """Read and return the contents of config.json in client."""
    path = 'config.json'  # DO NOT EDIT THIS PATH
    try:
        with open(path, 'r') as file:
            data = json.load(file)
            return data
    except FileNotFoundError:
        print(f"The file at {path} was not found.")
    except json.JSONDecodeError:
        print("Error decoding JSON from the file.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


# DO NOT CHANGE THIS FUNCTION DEFINITION (except for the return statement/type)
def read_config_flaskr():
    """Read and return the contents of config.json in flaskr."""
    path = 'config.json'  # DO NOT EDIT THIS PATH
    try:
        with open(path, 'r') as file:
            data = json.load(file)
            return data
    except FileNotFoundError:
        print(f"The file at {path} was not found.")
    except json.JSONDecodeError:
        print("Error decoding JSON from the file.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


def write_error(flow: http.HTTPFlow, error: str) -> None:
    i = 0
    while os.path.exists('errors/error_{}.txt'.format(i)):
        i += 1
    open('errors/error_{}.txt'.format(i), 'w').write(error)
    flow.comment = 'ERROR: {}'.format(error)
    flow.response = http.Response.make(500, flow.comment[7:])


def get_preshared_key() -> str:
    with open('../implementation/preshared_key.txt', 'r') as f:
        return f.read()

def generate_random_nonce(algorithm) -> str:
    """Generate a random nonce string of a specified length."""
    characters = string.ascii_letters + string.digits  # Letters and digits
    if algorithm == "rsa-oaep":
        return ''.join(random.choice(characters) for _ in range(20))
    else:
        return ''.join(random.choice(characters) for _ in range(16))

def encrypt(flow_type, encrypt_method, key, rsa_public_key_path, nonce, rsa_key_id, key_id):
    flow_type.headers["Content-Encoding"] = encrypt_method
    # Encrypt the request content depending on the method
    encrypted_content = ""
    if encrypt_method == "aes256cbc":
        encrypted_content = aes.encrypt(flow_type.raw_content, key, nonce.encode())
    elif encrypt_method == "salsa20":
        encrypted_content = salsa.encrypt(flow_type.raw_content, key, nonce.encode())
    elif encrypt_method == "rsa-oaep":
        encrypted_content = rsa.encrypt(flow_type.raw_content, rsa_public_key_path, nonce.encode())

    # Add the encryption header if we encrypted
    if encrypt_method == "aes256cbc" or encrypt_method == "salsa20" or encrypt_method == "rsa-oaep":
        if encrypt_method == "rsa-oaep":
            flow_type.headers["Encryption"] = 'keyid="{}", nonce="{}"'.format(rsa_key_id, nonce)
        else:
            flow_type.headers["Encryption"] = 'keyid="{}", nonce="{}"'.format(key_id, nonce)
        flow_type.raw_content = encrypted_content
        flow_type.headers['Content-Length'] = str(len(flow_type.raw_content))  # Update content length

def decrypt(flow_type, key, rsa_private_key_path):
    # get the nonce
    header_value = flow_type.headers['Encryption']  # Your original string
    nonce = header_value.split('nonce="')[1].split('"')[0]
    # get the encryption method
    encryption_method = flow_type.headers["Content-Encoding"]
    # Check if it has the correct size and method is correct
    if encryption_method == 'aes256cbc' and len(flow_type.raw_content) % 16 == 0:
        # Decrypt response content using the AES implementation
        flow_type.raw_content = aes.decrypt(flow_type.raw_content, key, nonce.encode())
    elif encryption_method == 'salsa20':
        # Decrypt response content using the SALSA implementation
        flow_type.raw_content = salsa.decrypt(flow_type.raw_content, key, nonce.encode())
    elif encryption_method == 'rsa-oaep':
        flow_type.raw_content = rsa.decrypt(flow_type.raw_content, rsa_private_key_path, nonce.encode())
    # Update content length
    flow_type.headers['Content-Length'] = str(len(flow_type.raw_content))
    # delete the encryption and content encoding headers after decryption
    del flow_type.headers['Encryption']
    del flow_type.headers["Content-Encoding"]


def authenticate(method, auth_key, auth_nonce, flow_type, key_id):
    flow_type.headers["Authorization"] = ""
    flow_type.headers["X-Authorization-Timestamp"] = str(int(datetime.now().timestamp()))
    header_names = sorted(flow_type.headers.keys())
    header_names_str = ";".join(header_names)
    # add authorization header before the string_to_auth without mac
    temp_header_value = '{} keyid="{}", nonce="{}", headers="{}"'.format(method, key_id, auth_nonce, header_names_str)
    flow_type.headers["Authorization"] = temp_header_value
    string_to_auth = mac_file.get_string_to_auth(flow_type)
    mac = ""
    if method == "sha1":
        mac = mac_file.generate_mac_sha1(string_to_auth, auth_key, auth_nonce.encode())
    elif method == "sha512hmac":
        mac = mac_file.generate_mac_hmac(string_to_auth, auth_key, auth_nonce.encode())

    # add the mac in the authorization header
    header_value = '{} keyid="{}", nonce="{}", headers="{}", mac="{}"'.format(method, key_id, auth_nonce,
                                                                              header_names_str, mac)
    flow_type.headers["Authorization"] = header_value

def authorize(flow_type, auth_method, key, auth_nonce, mac):
    # replace mac with empty string
    if flow_type.headers.get("Authorization", ""):
        auth_header = flow_type.headers.get("Authorization", "")
    else:
        auth_header = ""
    header_parts = auth_header.split(', ')
    header_parts = [part for part in header_parts if not part.startswith('mac=')]
    header_value_without_mac = ', '.join(header_parts)
    flow_type.headers["Authorization"] = header_value_without_mac

    # calculate time diff between the client and server
    if flow_type.headers.get("X-Authorization-Timestamp", ""):
        request_timestamp = int(flow_type.headers["X-Authorization-Timestamp"])
    else:
        request_timestamp = 0
    current_time = int(datetime.now().timestamp())
    diff_time = int(current_time) - int(request_timestamp)

    # if it differs more than 900 seconds the response will be rejected
    if diff_time > 900:
        flow_type = http.Response.make(401, b"Server response not authorized", {"Content-Type": "text/html",
                                                                                    "date": datetime.now().strftime(
                                                                                        "%a, %d %b %Y %H:%M:%S %Z"),
                                                                                    "connection": "close",
                                                                                    "WWW-Authenticate": auth_method})
        return

    # mac the response
    string_to_auth = mac_file.get_string_to_auth(flow_type)
    if auth_method == "sha1":
        new_mac = mac_file.generate_mac_sha1(string_to_auth, key, auth_nonce.encode())
    elif auth_method == "sha512hmac":
        new_mac = mac_file.generate_mac_hmac(string_to_auth, key, auth_nonce.encode())
    else:
        flow_type = http.Response.make(401, b"Server response not authorized", {"Content-Type": "text/html",
                                                                                    "date": datetime.now().strftime(
                                                                                        "%a, %d %b %Y %H:%M:%S %Z"),
                                                                                    "connection": "close",
                                                                                    "WWW-Authenticate": auth_method})
        return

    # If the content is not the same as the response we do not authorize it
    if mac != new_mac:
        flow_type = http.Response.make(401, b"Server response not authorized", {"Content-Type": "text/html",
                                                                                    "date": datetime.now().strftime(
                                                                                        "%a, %d %b %Y %H:%M:%S %Z"),
                                                                                    "connection": "close",
                                                                                    "WWW-Authenticate": auth_method})
        return

def get_active_session(session_path):
    """ This function checks if there exists an active session in the sessions directory
     that has been active for at least 10 seconds, if so returns the session"""
    sessions = os.listdir(session_path + '/')
    for i in sessions:
        with open(session_path + '/' + i, 'r') as f:
            data = json.load(f)
        session_time = data["end"] - int(datetime.now().timestamp())
        if session_time < 10:
            os.remove(session_path + '/' + i)
        else:
            return True, data
    return False, None

def garbage_collection(session_path):
    """ Removes all sessions that exceed the end time. """
    session_files = os.listdir(f"{session_path}/")
    for i in session_files:
        with open(session_path + '/' + i, 'r') as file:
            data = json.load(file)
        current_time = datetime.now().timestamp()
        # If the current time exceeds the end time, delete the file
        if current_time > data["end"]:
            os.remove(session_path + '/' + i)

def get_session_id(session_path):
    """ Creates a session id that does not exist yet in the sessions directory. """
    session_id = random.randint(0, 99999)
    if session_id not in os.listdir(session_path):
        return session_id
    else:
        while os.path.exists(session_path + str(session_id)):
            session_id = random.randint(0, 99999)
        return session_id

def get_auth_values(auth_header):
    # Split by spaces to get the auth method and rest of the string
    parts = auth_header.split(" ", 1)
    auth_method = parts[0]
    # Now split the remaining part by commas to get each key-value pair
    key_value_pairs = parts[1].split(", ")
    # Extract nonce and mac
    auth_nonce = key_value_pairs[1].split("=")[1].strip('"')
    mac = key_value_pairs[3].split("=")[1].strip('"')
    return auth_method, auth_nonce, mac