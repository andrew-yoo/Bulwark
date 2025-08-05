import secrets
from Crypto.Cipher import ChaCha20
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def xchacha(xchacha_key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Use the XChaCha20 cipher to encrypt data.

    Args:
        xchacha_key (bytes): The high-entropy key generated from password hashing
        plaintext (bytes): The plaintext to encrypt

    Returns:
        bytes: The encrypted ciphertext 
    """
    xchacha_nonce = secrets.token_bytes(24)
    cipher = ChaCha20.new(key=xchacha_key, nonce=xchacha_nonce)
    ciphertext = cipher.encrypt(plaintext)

    return xchacha_nonce, ciphertext

def xchacha_camellia_aes(xchacha_key: bytes, camellia_key: bytes, aes_key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Use XChaCha20, AES-256-CTR, and Serpent-256-CTR cascaded to encrypt data.
    """
    # XChaCha20
    xchacha_nonce = secrets.token_bytes(24)
    xchacha_cipher = ChaCha20.new(key=xchacha_key, nonce=xchacha_nonce)
    xchacha_ciphertext = xchacha_cipher.encrypt(plaintext)

    # Camellia-CTR
    camellia_nonce = secrets.token_bytes(16)
    camellia_cipher = Cipher(algorithm=algorithms.Camellia(key=camellia_key), mode=modes.CTR(camellia_nonce), backend=default_backend)
    camellia_encryptor = camellia_cipher.encryptor()
    camellia_ciphertext = camellia_encryptor.update(xchacha_ciphertext) + camellia_encryptor.finalize()

    # AES-256-CTR
    aes_nonce = secrets.token_bytes(16)
    aes_cipher = Cipher(algorithm=algorithms.AES256(key=aes_key), mode=modes.CTR(aes_nonce), backend=default_backend)
    aes_encryptor = aes_cipher.encryptor()
    aes_ciphertext = aes_encryptor.update(camellia_ciphertext) + aes_encryptor.finalize()

    return xchacha_nonce, camellia_nonce, aes_nonce, aes_ciphertext