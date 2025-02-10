import os
import traceback
from mitmproxy import http

import sys
import json


sys.path.append("..")  # Adds higher directory to python modules path. (Do not use .. in import)
from implementation import utils, key_exchange, check_cert
from implementation.encryption import aes, salsa, rsa
from datetime import datetime
import base64


# Check if the errors directory exists
if not os.path.exists('errors'):
    os.mkdir('errors')

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! #
# DO NOT ADD ANY GLOBAL CODE OUTSIDE THE REQUEST AND RESPONSE FUNCTIONS #
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! #

def request(flow: http.HTTPFlow) -> None:
    try:  # Do not edit this line

        if 'http://cns_flaskr/' != flow.request.url[:18]:  # Checks if the traffic is meant for the falskr website
            return
        flow.comment = 'cns_flaskr'  # Somehow indicate the flow is about traffic from cns_flaskr

        # read from the config
        config = utils.read_config_client()
        auth_method = config['mac']['method']
        encrypt_method = config['encryption']['method']
        # Generate a new random nonce
        nonce = utils.generate_random_nonce(encrypt_method)
        rsa_key_id = "cns_flaskr"
        rsa_public_key_path = config['encryption']['public_key_path']
        rsa_private_key_path = config['encryption']['private_key_path']

        # update the accept encoding with the method of the client
        temp = flow.request.headers["Accept-Encoding"]
        flow.request.headers["Accept-Encoding"] = temp + ", " + encrypt_method

        # If the sessions key exist we make use of the sessions
        if "sessions" in config:
            # Get the sessions paths
            session_path = config['sessions']['path']
            server_cert_path = config['sessions']['cert_save_path']
            ca_cert_path = config['sessions']['ca_cert_path']
            save_pub_key_path = config['sessions']['save_pub_key_path']

            # Delete all expired sessions
            utils.garbage_collection(session_path)

            # Check if there exists an active session, if so we get it
            active_session_exists, session = utils.get_active_session(session_path)
            if active_session_exists:
                key_id = session["id"]
                encrypt_key = base64.b64decode(session["encr_key"]).decode()
                auth_key = base64.b64decode(session["auth_key"]).decode()
            else:
                # Request the server certificate and put it in "keys/cns_flaskr.crt" (Client Hello)
                key_exchange.request_certificate()
                # Verify the servers certificate using the ca
                if check_cert.check_certificate(server_cert_path, ca_cert_path, save_pub_key_path):
                    # Use RSA encryption to send the two 100 character strings as random session keys to the server.
                    encrypt_key = os.urandom(50).hex()
                    auth_key = os.urandom(50).hex()
                    session_key = encrypt_key + '|' + auth_key
                    session_nonce = utils.generate_random_nonce("rsa-oaep")
                    # Encrypt the session key using RSA
                    encrypted_session_key = rsa.encrypt(session_key.encode(), save_pub_key_path, session_nonce.encode())
                    # Send the encrypted session key with the used nonce and get the servers response (Client Ack)
                    needed_header = 'keyid="{}", nonce="{}"'.format("cns_flaskr", session_nonce)
                    response_session = key_exchange.send_session_key(encrypted_session_key, {"Encryption": needed_header})

                    # decrypt the key_id and session end first
                    auth_header = response_session.headers["Authorization"]
                    # Get the authentication values that we need from the auth header
                    auth_method, auth_nonce, mac = utils.get_auth_values(auth_header)
                    utils.authorize(response_session, "sha512hmac", auth_key, auth_nonce, mac)
                    header_value = response_session.headers['Encryption']
                    nonce = header_value.split('nonce="')[1].split('"')[0]
                    utils.decrypt(response_session, encrypt_key, rsa_private_key_path)

                    key_id = int(response_session.raw_content[:5])
                    session_end = float(response_session.raw_content[5:])
                    # Create a session file
                    session = {"id": key_id, "end": session_end, "encr_key": base64.b64encode(encrypt_key.encode()).decode(),"auth_key": base64.b64encode(auth_key.encode()).decode()}
                    sess_path = f"{session_path}/session_{str(key_id)}.json"
                    # Write the session in the session_path file
                    with open(sess_path, "w", encoding="utf-8") as f:
                        json.dump(session, f)
                else:
                    # ca could not verify the certificate
                    return
        # otherwise we fall back to using pre-shared keys
        else:
            key_id = config['encryption']['keyid']
            encrypt_key = utils.get_preshared_key()
            auth_key = utils.get_preshared_key()

        # Authenticate first and then encrypt if auth_method, the method is sha1
        if auth_method == "sha1":
            utils.authenticate("sha1", auth_key, nonce, flow.request, key_id)

        # Encryption if there is content
        if int(flow.request.headers.get('Content-Length', 0)) > 0:
            utils.encrypt(flow.request, encrypt_method, encrypt_key, rsa_public_key_path, nonce, rsa_key_id, key_id)

        # Encrypt first and then authenticate if method is sha512hmac
        if auth_method == "sha512hmac":
            utils.authenticate("sha512hmac", auth_key, nonce, flow.request, key_id)

    except Exception as e:
        # Return an error reply to the client with the error message
        utils.write_error(flow, 'Client side - Request:\n{}\n{}'.format(e, traceback.format_exc()))


def response(flow: http.HTTPFlow) -> None:
    # If the response is an error message, return the message without performing any actions
    if flow.response.status_code >= 400:
        return
    try:
        if 'cns_flaskr' not in flow.comment:  # Checks if the traffic is meant for the falskr website
            return

        # Read the config of the client
        config = utils.read_config_client()
        rsa_private_key_path = config['encryption']['private_key_path']
        auth_header = flow.response.headers["Authorization"]

        # Get the authentication values that we need from the auth header
        auth_method, auth_nonce, mac = utils.get_auth_values(auth_header)

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
            utils.authorize(flow.response, auth_method, auth_key, auth_nonce, mac)
        elif auth_method == "sha1":
            pass
        else:
            flow.response = http.Response.make(401, b"Server response not authorized", {"Content-Type": "text/html",
                                                                                        "date": datetime.now().strftime(
                                                                                            "%a, %d %b %Y %H:%M:%S %Z"),
                                                                                        "connection": "close",
                                                                                        "WWW-Authenticate": auth_method})
            return

        # Check if the Encryption header is present, then decrypt
        if 'Encryption' in flow.response.headers:
            utils.decrypt(flow.response, encrypt_key, rsa_private_key_path)

        # if auth method is sha1 decrypt first and then authorize
        if auth_method == "sha1":
            utils.authorize(flow.response, auth_method, auth_key, auth_nonce, mac)
        elif auth_method == "sha512hmac":
            pass
        else:
            flow.response = http.Response.make(401, b"Server response not authorized", {"Content-Type": "text/html",
                                                                                        "date": datetime.now().strftime(
                                                                                            "%a, %d %b %Y %H:%M:%S %Z"),
                                                                                        "connection": "close",
                                                                                        "WWW-Authenticate": auth_method})
            return

    except Exception as e:
        # Return an error reply to the client with the error message
        utils.write_error(flow, 'Client side - Response:\n{}\n{}'.format(e, traceback.format_exc()))
