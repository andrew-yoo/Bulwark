import secrets
from Crypto.Cipher import ChaCha20

def xchacha(xchacha_key: bytes, plaintext: bytes) -> bytes:
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

    return ciphertext

def xchacha_aes_serpent():
    """
    Use XChaCha20, AES-256-CTR, and Serpent-256-CTR cascaded to encrypt data.
    """