# DO NOT CHANGE THIS FILE'S LOCATION: implementation/authentication/mac.py
import hashlib
from mitmproxy import http
from implementation.authentication.sha1 import SHA1

# DO NOT CHANGE THIS FUNCTION DEFINITION
def generate_mac_sha1(content: bytes, key: str, nonce: bytes) -> str:
    sha_init = SHA1()
    # data = (K + N + C)
    data = key.encode() + nonce + content
    # H (K + N + C)
    sha_init.hash(data.decode())
    out = sha_init.hexdigest()
    return out


def check_key_length(key: bytes, b_bits: int) -> bytes:
    if len(key) < b_bits:
        # zero's achteraan toevoegen tot b_bits
        out_key = key.ljust(b_bits, b'\x00')
        return out_key
    elif len(key) > b_bits:
        # SHA-512 to hash the key to b_bits
        out_key = hashlib.sha512(key).digest()
        return out_key
    else:
        return key

def check_nonce_length(nonce: bytes) -> bytes:
    if len(nonce) < 128:
        out_nonce = nonce.ljust(128, b'\x00')
        return out_nonce
    elif len(nonce) > 128:
        out_nonce = nonce[:128]
        return out_nonce
    else:
        return nonce

def get_ipad_opad(b_bits: int) -> tuple:
    # IPAD = 00110110 of in hex 0x36
    iPad = b'\x36' * b_bits
    # OPAD = 01011100 of in hex 0x5c
    oPad = b'\x5c' * b_bits
    # elk van dit bits moeten same zijn zoals de lengte van de SHA-512 block size
    return iPad,oPad

# DO NOT CHANGE THIS FUNCTION DEFINITION
def generate_mac_hmac(content: bytes, key: str, nonce: bytes) -> str:
    key_bits = key.encode()
    # We gebruiken SHA-512 voor HMAC dus b_bits = 1024 bits = 128 bytes
    b_bits = 128

    # GENERATING K+
    k_plus = check_key_length(key_bits,b_bits)
    # check if nonce is 128 bytes or not
    nonce = check_nonce_length(nonce)

    # To generate the S_bits we use 2 paddings IPAD and OPAD
    get_ipad_opad_bits = get_ipad_opad(b_bits)

    iPad = get_ipad_opad_bits[0]
    oPad = get_ipad_opad_bits[1]

    # Xor K+ with IPAD and OPAD (resultaat moet zelfde lengte hebben als de SHA-512 block size)
    s1 = bytearray(b_bits)
    s2 = bytearray(b_bits)

    for i in range(b_bits):
        # K+ XOR IPAD
        s1[i] = k_plus[i] ^ iPad[i]
        # K+ XOR OPAD
        s2[i] = k_plus[i] ^ oPad[i]

    m = nonce + content
    # H(s1 + M)
    hash_block1 = hashlib.sha512(s1 + m).digest()
    # H(s2 + H(s1 + M))
    hashcode = hashlib.sha512(s2 + hash_block1).hexdigest()
    return hashcode


# DO NOT CHANGE THIS FUNCTION DEFINITION
def get_string_to_auth(message: http.Message) -> bytes:
    string_to_auth = ""

    # Check if is a request message or response message
    if isinstance(message, http.Request):
        string_to_auth += message.method.upper() + "\n" + message.host + "\n" + message.path + "\n"

    # Extract headers excluding 'x-authenticated-id'
    sorted_headers = sorted((key.lower(), value) for key, value in message.headers.items())
    header_parts = []
    for header_name, header_value in sorted_headers:
        if header_name.lower() != 'x-authenticated-id':
            header_parts.append(header_name.lower() + ":" + header_value)

    # join them
    string_to_auth += '\n'.join(header_parts)

    # Check for content and append if present
    if message.raw_content and len(message.raw_content) > 0:
        string_to_auth += '\n' + message.raw_content.decode('utf-8', 'ignore')

    return string_to_auth.encode()


# You are allowed to make edits below here.
if __name__ == '__main__':
    key = 'axxgjjpvnon&d'
    nonce = 'b' * X  # (X = the needed amount of bytes in the nonce)  # Edit for testing
    content = 'my email address is: xx@uantwerpen.be'
    # (Results are in hex-string format)
    sha_1_mac = '951c9d29468008554c8f7960d29178c7a7a727fa'
    hmac_mac = 'bf191bfbfc071e3347002d52d62d2d25be7f5f638699ce816e76c4fb930f4b2037aa9fd23953c69e1eccd47f8e04b2d6eb6485dd9c32e1f5d65b14eee0c9d130'

    assert sha_1_mac == generate_mac_sha1(content.encode(), key, nonce)
    assert hmac_mac == generate_mac_hmac(content.encode(), key, nonce)
