# DO NOT CHANGE THIS FILE'S LOCATION: implementation/encryption/rsa.py
import hashlib
import math

from Crypto.PublicKey import RSA
import random

def Miller_Rabin(n, k):
    # MILLER & RABIN (ZIE YT VAN CODETHEORIE)
    #  STAP 1 : NOTEER n - 1 = 2^k * m
    # Als we n = 561 nemen als vb dan is d = 560 met k = 4 en m = 35
    # want 560/2^1 = 280 en 560/2^2 = 140 en 560/2^3 = 70 en 560/2^4 = 35 en 560/2^5 = 17.5 waar dit geen int is dus we stoppen bij 2^4 waar m = 35 en k = 4
    d = n - 1
    exp = 0
    while d % 2 == 0:
        exp += 1
        d //= 2
    # n - 1 = 2 ^ exp * d (herschrijving)
    for _ in range(k):
        # STAP 2 : kies een random a in range 2 tot n - 1
        a = random.randint(2, n - 1)
        # STAP 3 : x = a^d mod n
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(k - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def is_prime(n: int) -> bool:
    test_iterations = 100
    # BASE CASE
    if n <= 1:
        return False
    else:
        # ALGORITME
        if n % 2 == 0:
            if n == 2:
                return True
            else:
                return False
        else:
            # MILLER & RABIN
            return Miller_Rabin(n, test_iterations)


def get_prime_number(nr_bits: int) -> int:
    # We moeten in range blijven van 2^(nr_bits-1) en 2^(nr_bits) - 1 want nr_bits is het aantal bits die behouden moet worden
    lower = 1 << (nr_bits - 1)  # 2^(nr_bits-1)
    upper = (1 << nr_bits) - 1  # 2^(nr_bits) - 1
    while True:
        # Generate a random odd number within the range
        possible_odd_primenumber = random.randint(lower, upper) | 1
        # Check if the candidate is prime
        if is_prime(possible_odd_primenumber):
            return possible_odd_primenumber
        else:
            continue
def euclidean_algorithm(a: int, b: int) -> int:
    # ALGORITME
    while b != 0:
        a, b = b, a % b
    return abs(a)

def get_d(e, phi_n):
    # STAP 6) CALCULATE d such that d = e^-1 mod phi(n)
    def extended_euclidean_algorithm(a, b):
        old_x, x = 1, 0
        old_y, y = 0, 1
        while b != 0:
            q = a // b
            a, b = b, a % b  # gcd
            old_x, x = x, old_x - q * x
            old_y, y = y, old_y - q * y
        # a heeft de gcd
        return a, old_x, old_y

    # ZOEK DE INVERSE VAN van e adhv UEA
    gcd, x, y = extended_euclidean_algorithm(e, phi_n)
    # GCD MOET 1 ZIJN ANDERS BESTAAT ER GEEN MODULAR INVERSE
    if gcd == 1:
        # d = e^-1 %  phi(n)
        d = x % phi_n
        return d
    else:
        raise ValueError("No modular inverse exists for the given e and phi(n)")


def make_private_key(n, e, d, p, q, private_key_path):
    priv_key = RSA.construct((n, e, d, p, q))
    priv_key_pem = priv_key.exportKey()
    open(private_key_path, 'wb').write(priv_key_pem)

def make_public_key(n, e, public_key_path):
    pub_key = RSA.construct((n, e))
    pub_key_pem = pub_key.exportKey()
    open(public_key_path, 'wb').write(pub_key_pem)

def get_n(p,q) -> int:
    return p*q

def get_totient(p, q) -> int:
    return (p - 1) * (q - 1)

# DO NOT CHANGE THIS FUNCTION DEFINITION
def generate_keys(private_key_path: str, public_key_path: str, nr_bits: int) -> None:
    # Typically used RSA key sizes are 1024, 2048, and 4096 bits
    if nr_bits not in [1024, 2048, 4096]:
        raise ValueError("Invalid number of bits for RSA key generation")
    # STAP 1) SELECT TWO PRIME NUMBERS p and q
    p_bits,q_bits = nr_bits // 2, nr_bits // 2
    p = get_prime_number(p_bits)
    q = get_prime_number(q_bits)
    # STAP 2) CALCULATE n = p * q
    n = get_n(p,q)
    # STAP 3) CALCULATE phi(n) = (p - 1) * (q - 1)
    phi_n = get_totient(p, q)
    # STAP 4) SELECT e such that 1 < e < phi(n)
    e = random.randint(2, phi_n)
    d = None
    if nr_bits != 1024:
        # STAP 5) ZOLANG gcd(e, phi(n)) != 1 GA NAAR STAP 4
        while euclidean_algorithm(e, phi_n) != 1:
            e = random.randint(2, phi_n)
            d = get_d(e, phi_n)
            # e == d means e ni inverteerbaar
            if d == e:
                continue
    else:
        # Als we 1024 bits hebben dan is e = 65537 (Zie opgave)
        e = 65537
        d = get_d(e, phi_n)

    assert d is not None

    make_private_key(n, e, d, p, q, private_key_path)
    make_public_key(n, e, public_key_path)

def get_phash(P="") -> bytes:
    # P waar k H(P) eruit geef (ZIE TEKENING)
    if len(P) > pow(2,61) - 1:
        raise ValueError("P is greater than 2^61 - 1 for SHA-1 hashing")
    else:
        return hashlib.sha1(P.encode()).digest()

def get_rsa_block_size(n_bytes,lhash):
    return n_bytes - 2 * len(lhash) - 2

# DO NOT CHANGE THIS FUNCTION DEFINITION
def encrypt(content: bytes, key_path: str, nonce: bytes) -> bytes:
    # 1) Ik moet weten hoeveel bytes da er in de n zitten
    with open(key_path, 'rb') as f:
        pub_key = RSA.importKey(f.read())
    n = pub_key.n
    n_bytes = math.ceil(n.bit_length() / 8)
    block_length = get_rsa_block_size(n_bytes, get_phash())

    if block_length <= 0:
        raise ValueError("Block length is too small")
    else:
        # 2) Ik moet de content in blokken van block_length splitsen om OASP te kunnen toepassen
        split_contents = []
        for i in range(0, len(content), block_length):
            second_ptr = min(i + block_length, len(content))
            split_contents.append(content[i: second_ptr])
        # 3) Ik moet voor elk blok de RSAES OAEP ENCRYPTION toepassen adhv specs
        encrypted_blocks = []
        for block in split_contents:
            encrypted_block = RSAES_OAEP_ENCRYPTION(block, key_path, nonce)
            encrypted_blocks.append(encrypted_block)
        cipher = b''.join(encrypted_blocks)
        return cipher

# DO NOT CHANGE THIS FUNCTION DEFINITION
def decrypt(content: bytes, key_path: str, nonce: bytes) -> bytes:
    # 1) Ik moet weten hoeveel bytes da er in de n zitten
    with open(key_path, 'rb') as f:
        priv_key = RSA.importKey(f.read())
    n = priv_key.n
    n_bytes = math.ceil(n.bit_length() / 8)
    # 2) Ik moet de content in blokken van n_bytes splitsen om OASP te kunnen toepassen
    message_blocks = []
    for i in range(0, len(content), n_bytes):
        second_ptr = min(i + n_bytes, len(content))
        message_blocks.append(content[i: second_ptr])
    # 3) Ik moet voor elk blok de RSAES OAEP DECRYPTION toepassen adhv specs
    decrypted_blocks = []
    for block in message_blocks:
        decrypted_block = RSAES_OAEP_DECRYPTION(block, key_path, nonce)
        decrypted_blocks.append(decrypted_block)
    message = b''.join(decrypted_blocks)
    return message

def EME_OAEP_ENCODE(content_block:bytes, em_len:int, seed:bytes):
    # H(P) = P_hash
    p_hash = get_phash()
    hlen = len(p_hash)
    mlen = len(content_block)
    if len(content_block) > em_len - 2 * hlen - 1:
        raise ValueError("EME OAEP ENCODING ERROR: CONTENT BLOCK LENGTH IS TOO LONG")
    else:
        # Padding
        PS = b'\x00' * (em_len - mlen - 2 * hlen - 2)
        # DB = Lhash || PS || 0x01 || M
        DB = p_hash + PS + b'\x01' + content_block
        if len(DB) != em_len - hlen - 1:
            raise ValueError("EME OAEP ENCODING ERROR: DB LENGTH IS NOT CORRECT")
        else:
            # MGF GENERATION FOR DBMASK => first MGF IN TEKENING
            mask_length = em_len - hlen - 1
            mgf_db = MGF(seed, mask_length)
            # maskedDB = DB XOR dbMask
            maskedDB = bytearray()
            for x, y in zip(DB, mgf_db):
                maskedDB.append(x ^ y)
            maskedDB = bytes(maskedDB)
            # MGF GENERATION FOR SEEDMASK => second MGF IN TEKENING
            mgf_seed = MGF(maskedDB, hlen)
            # MaskedSeed = seed XOR seedMask
            Masked_seed = bytearray()
            for x, y in zip(seed, mgf_seed):
                Masked_seed.append(x ^ y)
            Masked_seed = bytes(Masked_seed)
            # EM = maskedSeed || maskedDB
            EM = b'\x00' + Masked_seed + maskedDB
            if len(EM) != em_len:
                raise ValueError("EME OAEP ENCODING ERROR: EM LENGTH IS NOT CORRECT")
            else:
                return EM

def RSAES_OAEP_ENCRYPTION(content_block:bytes, rsa_public_keypath:str,nonce:bytes):
    # STEP 1) READ PUBLIC KEY
    with open(rsa_public_keypath, 'rb') as f:
        pub_key = RSA.importKey(f.read())
    n = pub_key.n
    e = pub_key.e
    # hoeveel bytes zitten er in n
    n_bytes = math.ceil(n.bit_length() / 8)

    EM = EME_OAEP_ENCODE(content_block, n_bytes, nonce)
    m = OS2IP(EM)
    c = RSAEP((n,e),m)
    C = I2OSP(c,n_bytes)
    if len(C) != n_bytes:
        raise ValueError("RSAES OAEP ENCRYPTION ERROR: CIPHER LENGTH LENGTH IS NOT CORRECT")
    else:
        return C

def EME_OAEP_DECODE(EM, em_len, nonce_seed):
    if len(EM) < 2 * len(get_phash()) + 1:
        raise ValueError("EME OAEP DECODING ERROR: EM LENGTH IS TOO SHORT")
    else:
        p_hash = get_phash()
        hlen = len(p_hash)
        # separate EM into maskedSeed and maskedDB
        MaskedSeed = EM[1:hlen + 1] # first hlen octets of EM
        MaskedDB = EM[hlen + 1:] # remaining octets of EM
        # mask generation function (for seed)
        seedMask = MGF(MaskedDB, hlen)
        # seed = maskedSeed XOR seedMask
        seed = bytearray()
        for x, y in zip(MaskedSeed, seedMask):
            seed.append(x ^ y)
        seed = bytes(seed)
        # EXTRA CHECK VOOR DEN NONCE
        if seed != nonce_seed:
            raise ValueError("EME OAEP DECODING ERROR: SEED IS NOT EQUAL TO NONCE")
        else:
            # gebruik mgf voor (DbMask) (EMLEN - HLEN)
            dbMask = MGF(seed, len(EM) - hlen)
            # XOR maskedDB and dbMask
            DB = bytearray()
            for x, y in zip(MaskedDB, dbMask):
                DB.append(x ^ y)
            DB = bytes(DB)
            # split DB in pHash, PS and M en voer de checks uit zie specs
            pHash = DB[:hlen]
            # seperator moet 01 zijn
            if b'\x01' not in DB[hlen:]:
                raise ValueError("EME OAEP DECODING ERROR: PS AND M SEPARATOR OCTET 01 NOT FOUND")
            else:
                PS = DB[hlen:].split(b'\x01')[0]
                M = DB[hlen + len(PS) + 1:]
                # check of PS en pHash correct zijn
                if PS != b'\x00' * (em_len - len(M) - 2 * hlen - 2):
                    raise ValueError("EME OAEP DECODING ERROR: LENGTH OF PS IS NOT CORRECT")
                else:
                    if pHash != p_hash:
                        raise ValueError("EME OAEP DECODING ERROR: pHash is not equal to Lhash")
                    else:
                        return M

def RSAES_OAEP_DECRYPTION(ciphertext:bytes, rsa_private_keypath:str,nonce:bytes):
    # STEP 1) READ PRIVATE KEY
    with open(rsa_private_keypath, 'rb') as f:
        priv_key = RSA.importKey(f.read())
    n = priv_key.n
    d = priv_key.d
    # hoeveel bytes zitten er in n
    n_bytes = math.ceil(n.bit_length() / 8)
    if len(ciphertext) != n_bytes:
        raise ValueError("RSAES OAEP DECRYPTION ERROR: CIPHERTEXT LENGTH IS NOT CORRECT")
    else:
        # STEP 2) OS2IP
        c = OS2IP(ciphertext)
        # STEP 3) RSADP
        m = RSADP((n,d),c)
        # STEP 4) I2OSP
        EM = I2OSP(m,n_bytes)
        # STEP 5) EME-OAEP-DECODE
        M = EME_OAEP_DECODE(EM,n_bytes,nonce)
        hlen = len(get_phash())
        if len(M) > n_bytes - 2 - 2 * hlen:
            raise ValueError("RSAES OAEP DECRYPTION ERROR: MESSAGE LENGTH IS TOO LONG")
        else:
            return M


def I2OSP(x,l):
    if x >= pow(256,l):
        raise ValueError("integer too large to do I2OSP")
    else:
        X = x.to_bytes(l, 'big')
        return X

def MGF(Z, l):
    hlen = len(get_phash())
    if l > pow(2, 32) * hlen:
        raise ValueError("mask too long")
    else:
        T = b''
        for i in range(math.ceil(l / hlen)):
            C = I2OSP(i, 4)
            T += hashlib.sha1(Z + C).digest()
        mask = T[:l]
        return mask


def OS2IP(X):
    return int.from_bytes(X, 'big')

def RSAEP(rsa_public_key:tuple,m:int):
    # rsa_public_key = (n,e)
    n,e = rsa_public_key[0],rsa_public_key[1]
    if m < 0 or m > n:
        raise ValueError("RSAEP: message representative out of range")
    else:
        c = pow(m,e,n)
        return c

def RSADP(rsa_private_key:tuple,c:int):
    # rsa_private_key = (n,d)
    n,d = rsa_private_key[0],rsa_private_key[1]
    if c < 0 or c > n:
        raise ValueError("RSADP: ciphertext representative out of range")
    else:
        m = pow(c,d,n)
        return m



if __name__ == '__main__':
    private_key = './test_pri.pem'
    public_key = './test_pu.pem'
    nonce = 'M9sAsNS7ZPThI01T8SvX'  # (x = needed length nonce)
    plaintext = '4fd7c6b8fdcfceff3696db7933d21c525ffb6b69d3997bba7c4de3ac3da755819fae55d014c41e544868069be18d64687985418524c53144f2ef05c7142ce4ca396cfd06fd99e202e6ddbb32b9cd75e91c7e6599de9aa4c3786e689096b72ec9b272695e'
    print("Plaintext: ", plaintext)
    print("Test Encrypted Ciphertext: ", encrypt(plaintext.encode(), public_key, nonce.encode()))
    ciphertext = encrypt(plaintext.encode(), public_key, nonce.encode())
    print("Ciphertext: ", ciphertext)
    print("Test Decrypted Ciphertext: ", decrypt(ciphertext, private_key, nonce.encode()).decode())

    assert plaintext == decrypt(ciphertext, private_key, nonce.encode()).decode()
