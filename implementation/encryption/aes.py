# DO NOT CHANGE THIS FILE'S LOCATION: implementation/encryption/aes.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

def hash_key(pre_shared_key: str) -> bytes:
    """Hash the pre-shared key using SHA-256 to get a 256-bit key."""
    return hashlib.sha256(pre_shared_key.encode()).digest()

# DO NOT CHANGE THIS FUNCTION DEFINITION
def encrypt(content: bytes, key: str, nonce: str) -> bytes:
    """Encrypts the provided content using AES-256-CBC."""
    # cut the nonce to 16 bytes
    iv = nonce[:16]

    # Create AES cipher
    hashed_key = hash_key(key)
    cipher = AES.new(hashed_key, AES.MODE_CBC, iv)

    # Pad content and encrypt
    pad_content = pad(content, AES.block_size)
    encrypted_data = cipher.encrypt(pad_content)

    return encrypted_data


# DO NOT CHANGE THIS FUNCTION DEFINITION
def decrypt(content: bytes, key: str, nonce: str) -> bytes:
    """Decrypts the provided encrypted content using AES-256-CBC."""
    # cut nonce to 16 bytes
    iv = nonce[:16]

    # Create AES cipher
    hashed_key = hash_key(key)
    cipher = AES.new(hashed_key, AES.MODE_CBC, iv)

    # Decrypt and unpad content
    decrypted_data = cipher.decrypt(content)
    unpad_data = unpad(decrypted_data, AES.block_size)

    return unpad_data


if __name__ == '__main__':
    key = 'password'
    nonce = 'this is a nonce that is too long, cut it where necessary.'
    plaintext = 'this is some text to test AES'
    ciphertext = b'2\xabf.\xed+/\xe5J\x1b \xc1\x1f|\xe5\xb7I\xd4 R\x81\nE\x0b9\xc8\x05\x99\x14\xceW\xcf'

    print("Plaintext: ",  plaintext)
    print("Test Encrypted Ciphertext: ", encrypt(plaintext.encode(), key, nonce.encode()))

    assert ciphertext == encrypt(str.encode(plaintext), key, str.encode(nonce))

    print("Ciphertext: ", ciphertext)
    print("Test Decrypted Ciphertext: ", decrypt(ciphertext, key, nonce.encode()).decode())

    assert plaintext == decrypt(encrypt(str.encode(plaintext), key, str.encode(nonce)), key, str.encode(nonce)).decode()
