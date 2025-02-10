import os
from mitmproxy import http
import traceback

import sys
import json
sys.path.append("..")  # Adds higher directory to python modules path. (Do not use .. in import)
from implementation import utils, key_exchange
from implementation.encryption import rsa
from datetime import datetime
import base64


# Check if the errors directory exists
if not os.path.exists('errors'):
    os.mkdir('errors')

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! #
# DO NOT ADD ANY GLOBAL CODE OUTSIDE THE REQUEST AND RESPONSE FUNCTIONS #
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! #

def request(flow: http.HTTPFlow) -> None:
    try:
        if 'http://cns_flaskr/' != flow.request.url[:18]:  # Checks if the traffic is meant for the flaskr website
            return
        flow.comment = 'cns_flaskr'  # Somehow indicate the flow is about traffic from cns_flaskr

        # read config of flaskr
        config = utils.read_config_flaskr()
        rsa_private_key_path = config['encryption']['private_key_path']

        # The server responds to the Client Hello with its certificate, which is signed by a CA (Server Hello).
        if flow.request.path == '/client_hello':
            flow.response = key_exchange.create_certificate_response()
            return

        # The server will decrypt the two session keys using its private key and create a session for 1 min (Server Ack)
        if flow.request.path == '/client_ack':
            # Get the sessions paths
            session_path = config['sessions']['path']
            # Get the nonce that we used to encrypt the session keys
            header_value = flow.request.headers['Encryption']
            nonce = header_value.split('nonce="')[1].split('"')[0]

            # split the decrypted session key to get the encrypt key and auth key
            decrypted_session_key = rsa.decrypt(flow.request.raw_content, rsa_private_key_path, nonce.encode()).decode()
            decrypted_session_key_split = decrypted_session_key.split("|")
            encrypt_key = decrypted_session_key_split[0].encode()
            auth_key = decrypted_session_key_split[1].encode()

            # Create a session file of 1 min
            session_id = utils.get_session_id(session_path)
            # The session will be valid for 1 min (60 sec)
            session_end_time = datetime.now().timestamp() + 60
            data = {"id": session_id, "end": session_end_time, "encr_key": base64.b64encode(encrypt_key).decode(), "auth_key": base64.b64encode(auth_key).decode()}
            sess_path = f"{session_path}/session_{str(session_id)}.json"
            with open(sess_path, "w", encoding="utf-8") as f:
                json.dump(data, f)

            flow.response = key_exchange.create_acknowledgement_response(session_id, session_end_time)
            return

        accept_macs = config["mac"]["methods"]
        accept_macs_str = ",".join(accept_macs)
        auth_header = flow.request.headers["Authorization"]
        # Get the authentication values that we need from the auth header
        auth_method, auth_nonce, mac = utils.get_auth_values(auth_header)

        # check if auth method is supported by the flaskr
        if auth_method not in accept_macs:
            flow.response = http.Response.make(401, b"Not authorized", {"Content-Type": "text/html",
                                                                        "date": datetime.now().strftime(
                                                                            "%a, %d %b %Y %H:%M:%S %Z"),
                                                                        "connection": "close",
                                                                        "WWW-Authenticate": accept_macs_str})
            return

        # If the sessions key exist we make use of the sessions
        if "sessions" in config:
            # Get the sessions paths
            session_path = config['sessions']['path']
            # Delete all expired sessions
            utils.garbage_collection(session_path)

            # Check if there exists an active session, if so we get it
            active_session_exists, session = utils.get_active_session(session_path)
            if active_session_exists:
                encrypt_key = base64.b64decode(session["encr_key"]).decode()
                auth_key = base64.b64decode(session["auth_key"]).decode()
            else:
                # No active session
                return
        # otherwise we fall back to using pre-shared keys
        else:
            encrypt_key = utils.get_preshared_key()
            auth_key = utils.get_preshared_key()

        # if auth method is sha512hmac authorize first and then decrypt
        if auth_method == "sha512hmac":
            utils.authorize(flow.request, auth_method, auth_key, auth_nonce, mac)

        # Check if the Encryption header is present, then decrypt
        if 'Encryption' in flow.request.headers:
            utils.decrypt(flow.request, encrypt_key, rsa_private_key_path)

        # if auth method is sha1 decrypt first and then authorize
        if auth_method == "sha1":
            utils.authorize(flow.request, auth_method, auth_key, auth_nonce, mac)

        # DO NOT PUT ANY CODE UNDER THIS COMMENT, THIS SHOULD BE THE LAST PART OF THE FUNCTION
        # If the traffic is meant for the flaskr website, redirect it to the webserver (reverse proxy)
        flow.request.host = 'localhost'  # Important do not delete
        flow.request.port = 5000

        # remove any non-printable characters from message body for hacking session
        if len(flow.request.raw_content) > 0:
            allowed = set(range(32, 127)).union({9, 10, 13})
            flow.request.raw_content = bytes([b for b in flow.request.raw_content if b in allowed])
            flow.request.headers['Content-Length'] = str(len(flow.request.raw_content))

    except Exception as e:
        # Return an error reply to the client with the error message
        utils.write_error(flow, 'Server side - Request:\n{}\n{}'.format(e, traceback.format_exc()))
        # Do not let the message go through to the website, nor the reverse proxy. Direct to random port
        flow.request.port = 5003


def response(flow: http.HTTPFlow) -> None:
    # If the response is an error message, return the message without performing any actions
    if flow.response.status_code >= 400:
        return
    try:
        if 'cns_flaskr' not in flow.comment:  # Checks if the traffic is meant for the flaskr website
            return

        # read config of flaskr
        config = utils.read_config_flaskr()
        accept_encodings = config["encryption"]["methods"]
        rsa_public_key_path = config['encryption']['public_key_path']
        rsa_key_id = "cns_client"

        # If the sessions key exist we make use of the sessions
        if "sessions" in config:
            session_path = config['sessions']['path']
            # Delete all expired sessions
            utils.garbage_collection(session_path)

            # Check if there exists an active session, if so we get it
            active_session_exists, session = utils.get_active_session(session_path)
            if active_session_exists:
                encrypt_key = base64.b64decode(session["encr_key"]).decode()
                auth_key = base64.b64decode(session["auth_key"]).decode()
                key_id = session["id"]
            else:
                # No active session
                return
        # otherwise we fall back to using pre-shared keys
        else:
            encrypt_key = utils.get_preshared_key()
            auth_key = utils.get_preshared_key()
            key_id = config['encryption']['keyid']

        # If it is a client ack we need to encrypt the session key and end time using rsa en authenticate with hmac
        if flow.request.path == '/client_ack':
            nonce = utils.generate_random_nonce("aes256cbc")
            utils.encrypt(flow.response, "aes256cbc", encrypt_key, rsa_public_key_path, nonce, rsa_key_id, key_id)
            utils.authenticate("sha512hmac", auth_key, nonce, flow.response, key_id)
        # Normal traffic (look at client chosen method for encryption and authentication
        else:
            # Split by spaces to get the auth method and rest of the string
            auth_header = flow.request.headers["Authorization"]
            # Split by spaces to get the auth method and rest of the string
            parts = auth_header.split(" ", 1)
            auth_method = parts[0]
            # get the encryption method of the client
            temp_encoding = flow.request.headers["Accept-Encoding"]
            accepted_encodings = [encoding.strip() for encoding in temp_encoding.split(",")]
            encryption_method = accepted_encodings[-1]
            nonce = utils.generate_random_nonce(encryption_method)

            # Authenticate first and then encrypt if the method is sha1
            if auth_method == "sha1":
                utils.authenticate("sha1", auth_key, nonce, flow.response, key_id)
            # Encryption if there is content
            if int(flow.response.headers.get('Content-Length', 0)) > 0:
                # check if the encryption method is supported by the flaskr
                if encryption_method not in accept_encodings:
                    flow.response = http.Response.make(
                        400,
                        "Not a valid encoding method",
                        {"Known-Methods": ", ".join(accept_encodings)}
                    )
                    return
                # Encrypt
                utils.encrypt(flow.response, encryption_method, encrypt_key, rsa_public_key_path, nonce, rsa_key_id,
                              key_id)

            # Encrypt first and then authenticate if method is sha512hmac
            if auth_method == "sha512hmac":
                utils.authenticate("sha512hmac", auth_key, nonce, flow.response, key_id)

    except Exception as e:
        # Return an error reply to the client with the error message
        utils.write_error(flow, 'Server side - Response:\n{}\n{}'.format(e, traceback.format_exc()))
