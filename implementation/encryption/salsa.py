# DO NOT CHANGE THIS FILE'S LOCATION: implementation/encryption/salsa.py
from implementation.encryption.aes import hash_key

def to_little_endian(byte_data: bytes) -> int:
    return int.from_bytes(byte_data, byteorder='little')

def check_and_split_nonce(nonce: bytes) -> tuple:
    # Check the length of the nonce
    if len(nonce) < 8:
        # Pad the nonce with null bytes to make it 8 bytes long
        nonce = nonce.rjust(8, b'\x00')
    elif len(nonce) > 8:
        # Truncate the nonce to 8 bytes if it is longer than 8 bytes
        nonce = nonce[:8]

    assert len(nonce) == 8
    # split the nonce
    nonce1 = nonce[:4]
    nonce1 = to_little_endian(nonce1)
    nonce2 = nonce[4:8]
    nonce2 = to_little_endian(nonce2)
    out = (nonce1, nonce2)
    return out

def split_key(key: bytes) -> tuple:
    assert len(key) == 32 or len(key) == 16
    if len(key) == 32:
        K1 = key[:4]
        K1 = to_little_endian(K1)
        K2 = key[4:8]
        K2 = to_little_endian(K2)
        K3 = key[8:12]
        K3 = to_little_endian(K3)
        K4 = key[12:16]
        K4 = to_little_endian(K4)
        K5 = key[16:20]
        K5 = to_little_endian(K5)
        K6 = key[20:24]
        K6 = to_little_endian(K6)
        K7 = key[24:28]
        K7 = to_little_endian(K7)
        K8 = key[28:32]
        K8 = to_little_endian(K8)
        return K1, K2, K3, K4, K5, K6, K7, K8
    elif len(key) == 16:
        K1 = key[:4]
        K1 = to_little_endian(K1)
        K2 = key[4:8]
        K2 = to_little_endian(K2)
        K3 = key[8:12]
        K3 = to_little_endian(K3)
        K4 = key[12:16]
        K4 = to_little_endian(K4)
        K5 = K1
        K6 = K2
        K7 = K3
        K8 = K4
        return K1, K2, K3, K4, K5, K6, K7, K8
    else:
        raise ValueError("Key length is not 16 or 32 bytes")

def split_constants(key_length)-> tuple:
    cte_string = ""
    if key_length == 16:
        cte_string = "expand 16-byte k"
    if key_length == 32:
        cte_string = "expand 32-byte k"
    c1 = cte_string[:4]
    c2 = cte_string[4:8]
    c3 = cte_string[8:12]
    c4 = cte_string[12:16]

    c1_bytes = c1.encode('ascii')
    c2_bytes = c2.encode('ascii')
    c3_bytes = c3.encode('ascii')
    c4_bytes = c4.encode('ascii')

    C1 = to_little_endian(c1_bytes)
    C2 = to_little_endian(c2_bytes)
    C3 = to_little_endian(c3_bytes)
    C4 = to_little_endian(c4_bytes)

    return C1, C2, C3, C4


def split_position(position: int) -> tuple:
    # p1: lower 32 bits
    p1 = (position & 0xFFFFFFFF).to_bytes(4, byteorder='little')
    # p2: upper 32 bits
    p2 = ((position >> 32) & 0xFFFFFFFF).to_bytes(4, byteorder='little')

    P1 = to_little_endian(p1)
    P2 = to_little_endian(p2)
    return P1, P2


def init_state(keys, nonce, constants,positions):
    # create the matrix
    matrix = [
        constants[0], keys[0], keys[1], keys[2],
        keys[3], constants[1], nonce[0], nonce[1],
        positions[0],positions[1], constants[2], keys[4],
        keys[5], keys[6], keys[7], constants[3]
    ]

    return matrix


def rotate_left(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

def quarter_round(y0, y1, y2, y3):
    z1 = y1 ^ rotate_left((y0 + y3)& 0xFFFFFFFF, 7)
    z2 = y2 ^ rotate_left((z1 + y0)& 0xFFFFFFFF, 9)
    z3 = y3 ^ rotate_left((z2 + z1)& 0xFFFFFFFF, 13)
    z0 = y0 ^ rotate_left((z3 + z2)& 0xFFFFFFFF, 18)


    return z0, z1, z2, z3

def column_round(matrix):
    # uitvoering van de quarter round op de kolommen
    y0,y4,y8,y12 = quarter_round(matrix[0], matrix[4], matrix[8], matrix[12])
    y5,y9,y13,y1 = quarter_round(matrix[5], matrix[9], matrix[13], matrix[1])
    y10,y14,y2,y6 = quarter_round(matrix[10], matrix[14], matrix[2], matrix[6])
    y15,y3,y7,y11 = quarter_round(matrix[15], matrix[3], matrix[7], matrix[11])

    # update the matrix
    matrix[0], matrix[4], matrix[8], matrix[12] = y0,y4,y8,y12
    matrix[5], matrix[9], matrix[13], matrix[1] = y5,y9,y13,y1
    matrix[10], matrix[14], matrix[2], matrix[6] = y10,y14,y2,y6
    matrix[15], matrix[3], matrix[7], matrix[11] = y15,y3,y7,y11
    return matrix

def row_round(matrix):
    # uitvoering van de quarter round op de rijen
    z0,z1,z2,z3 = quarter_round(matrix[0], matrix[1], matrix[2], matrix[3])
    z5,z6,z7,z4 = quarter_round(matrix[5], matrix[6], matrix[7], matrix[4])
    z10,z11,z8,z9 = quarter_round(matrix[10], matrix[11], matrix[8], matrix[9])
    z15,z12,z13,z14 = quarter_round(matrix[15], matrix[12], matrix[13], matrix[14])

    # update the matrix
    matrix[0], matrix[1], matrix[2], matrix[3] = z0,z1,z2,z3
    matrix[5], matrix[6], matrix[7], matrix[4] = z5,z6,z7,z4
    matrix[10], matrix[11], matrix[8], matrix[9] = z10,z11,z8,z9
    matrix[15], matrix[12], matrix[13], matrix[14] = z15,z12,z13,z14
    return matrix


def double_round(matrix):
    W = matrix[:]
    # column round
    column_round(W)
    # row round
    row_round(W)
    return W



# DO NOT CHANGE THIS FUNCTION DEFINITION
def encrypt(content: bytes, key: str, nonce: bytes) -> bytes:
    # Decrypt just like the encrypt function does
    hashed_key = hash_key(key)
    k1, k2, k3, k4, k5, k6, k7, k8 = split_key(hashed_key)
    listify_keys = [k1, k2, k3, k4, k5, k6, k7, k8]

    # Initial nonce setup
    n1, n2 = check_and_split_nonce(nonce)
    listify_nonces = [n1, n2]

    # Constants for Salsa20
    c1, c2, c3, c4 = split_constants(len(hashed_key))
    listify_constants = [c1, c2, c3, c4]

    decrypted_content = bytearray()  # To store the decrypted result
    counter = 0
    # Split content into 64-byte blocks
    for block_start in range(0, len(content), 64):
        p = split_position(counter)
        block = content[block_start:block_start + 64]
        # Initialize the matrix for this block (with the updated counter)
        init_matrix = init_state(listify_keys, listify_nonces, listify_constants, p)
        copyMatrix = init_matrix.copy()
        # Apply 10 rounds (alternating column and row rounds)
        for _ in range(10):
            init_matrix = double_round(init_matrix)

        # Add the original matrix to the new matrix
        for i in range(16):
            init_matrix[i] = (init_matrix[i] + copyMatrix[i]) % (2 ** 32)  # Modular reduction

        # Convert matrix to keystream (16 words of 4 bytes = 64 bytes)
        keystream = bytearray()
        for word in init_matrix:
            keystream.extend(word.to_bytes(4, byteorder='little'))

        # XOR block with keystream to get the decrypted plaintext
        decrypted_block = bytearray(len(block))
        for i in range(len(block)):
            decrypted_block[i] = block[i] ^ keystream[i]

        # Append decrypted block to the result
        decrypted_content.extend(decrypted_block)

        # Increment the counter
        counter += 1
    # Return raw bytes, don't decode here
    return bytes(decrypted_content)


# DO NOT CHANGE THIS FUNCTION DEFINITION
def decrypt(content: bytes, key: str, nonce: bytes) -> bytes:
    out = encrypt(content, key, nonce)
    return out


if __name__ == '__main__':
    key = 'password'
    nonce = 'this is a nonce that is too long, cut it where necessary.'
    plaintext = 'this is some text to test Salsa'
    ciphertext = b'\x0e/\x81\xe0:D\xe8\xabQ=B\x8d\xcc\xa9\xeaBd\xbfy1\x94|\xa3Ja\x83\x85M\x99\tG'

    print("Plaintext: ",  plaintext)
    print("Test Encrypted Ciphertext: ", encrypt(plaintext.encode(), key, nonce.encode()))

    assert ciphertext == encrypt(str.encode(plaintext), key, str.encode(nonce))

    print("Ciphertext: ", ciphertext)
    print("Test Decrypted Ciphertext: ", decrypt(ciphertext, key, nonce.encode()).decode())

    assert plaintext == decrypt(encrypt(str.encode(plaintext), key, str.encode(nonce)), key, str.encode(nonce)).decode()
