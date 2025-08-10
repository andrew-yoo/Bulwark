import secrets
from Crypto.Cipher import ChaCha20
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def xchacha_encrypt(xchacha_key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Use the XChaCha20 cipher to encrypt data.

    Args:
        xchacha_key (bytes): The high-entropy key generated from password hashing
        plaintext (bytes): The plaintext to encrypt

    Returns:
        tuple: nonce, ciphertext
    """
    xchacha_nonce = secrets.token_bytes(24)
    xchacha_cipher = ChaCha20.new(key=xchacha_key, nonce=xchacha_nonce)
    xchacha_ciphertext = xchacha_cipher.encrypt(plaintext)

    return xchacha_nonce, xchacha_ciphertext

def xchacha_decrypt(xchacha_key: bytes, xchacha_nonce:bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt data with XChaCha20
    
    Args:
        xchacha_key (bytes): The secret key used for encryption
        xchacha_nonce (bytes): The randomly-generated nonce used for encryption
        ciphertext (bytes): The encrypted ciphertext
    
    Returns:
        bytes: Plaintext
    """
    xchacha_cipher = ChaCha20.new(key=xchacha_key, nonce=xchacha_nonce)
    plaintext = xchacha_cipher.decrypt(ciphertext)
    
    return plaintext

def xchacha_camellia_aes_encrypt(xchacha_key: bytes, camellia_key: bytes, aes_key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Use XChaCha20, Camellia-256-OFB, and AES-256-CTR cascaded to encrypt data.

    Args:
        xchacha_key (bytes): The key for XChaCha20
        camellia_key (bytes): The key for Camellia (32 bytes)
        aes_key (bytes): The key for AES (32 bytes)
        plaintext (bytes): The plaintext to encrypt

    Returns:
        tuple: XChaCha nonce, Camellia nonce, AES nonce, ciphertext
    """
    # XChaCha20
    xchacha_nonce = secrets.token_bytes(24)
    xchacha_cipher = ChaCha20.new(key=xchacha_key, nonce=xchacha_nonce)
    xchacha_ciphertext = xchacha_cipher.encrypt(plaintext)

    # Camellia-CTR
    camellia_nonce = secrets.token_bytes(16)
    camellia_cipher = Cipher(algorithm=algorithms.Camellia(key=camellia_key), mode=modes.OFB(camellia_nonce), backend=default_backend)
    camellia_encryptor = camellia_cipher.encryptor()
    camellia_ciphertext = camellia_encryptor.update(xchacha_ciphertext) + camellia_encryptor.finalize()

    # AES-256-CTR
    aes_nonce = secrets.token_bytes(16)
    aes_cipher = Cipher(algorithm=algorithms.AES256(key=aes_key), mode=modes.CTR(aes_nonce), backend=default_backend)
    aes_encryptor = aes_cipher.encryptor()
    aes_ciphertext = aes_encryptor.update(camellia_ciphertext) + aes_encryptor.finalize()

    return xchacha_nonce, camellia_nonce, aes_nonce, aes_ciphertext

def xchacha_camellia_aes_decrypt(xchacha_key: bytes, xchacha_nonce: bytes, camellia_key: bytes, camellia_nonce: bytes, aes_key: bytes, aes_nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt cascaded data using XChaCha20, Camellia-256-OFB, and AES-256-CTR.

    Args:
        xchacha_key (bytes): The 32 byte key used for XChaCha20 encryption
        xchacha_nonce (bytes): The 24 bytes nonce used for XChaCha20 encryption
        camellia_key (bytes): The 32 byte key used for Camellia-256-OFB encryption
        camellia_nonce (bytes): The 16 byte nonce used for Camellia-256-OFB encryption
        aes_key (bytes): The 32 byte key used for AES-256-CTR encryption
        aes_nonce (bytes): The 16 byte nonce used for AES-256-CTR encryption
        ciphertext (bytes): The encrypted ciphertext
    
    Returns:
        bytes: Plaintext
    """
    # AES-256-CTR
    aes_cipher = Cipher(algorithm=algorithms.AES256(key=aes_key), mode=modes.CTR(aes_nonce), backend=default_backend)
    aes_decryptor = aes_cipher.decryptor()
    camellia_ciphertext = aes_decryptor.update(ciphertext) + aes_decryptor.finalize()

    # Camellia-256-OFB
    camellia_cipher = Cipher(algorithm=algorithms.Camellia(key=camellia_key), mode=modes.OFB(camellia_nonce), backend=default_backend)
    camellia_decryptor = camellia_cipher.decryptor()
    xchacha_ciphertext = camellia_decryptor.update(camellia_ciphertext) + camellia_decryptor.finalize()

    # XChaCha20
    xchacha_cipher = ChaCha20.new(key=xchacha_key, nonce=xchacha_nonce)
    plaintext = xchacha_cipher.decrypt(xchacha_ciphertext)

    return plaintext