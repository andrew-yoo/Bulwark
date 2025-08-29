from blake3 import blake3

def mac(mac_key: bytes, message: bytes) -> bytes:
    """
    Use keyed Blake3 as a MAC.

    Args:
        key (bytes): The key used for hashing
        data (bytes): The message to hash

    Returns:
        bytes: Message Authentication Code
    """
    if len(mac_key) != 32:
        raise ValueError("MAC key must be 32 bytes.")
    
    return blake3(message, key=mac_key).digest()

def check_mac(code: bytes, mac_key:bytes, message: bytes):
    """
    Verifies the authenticity of a code using Blake3 keyed hashing.

    Args:
        code (bytes): The provided MAC
        mac_key (bytes): The key used for hashing
        message (bytes): The message to authenticate

    Returns:
        bool: Whether or not the message is authentic
    """
    hash = blake3(message, key=mac_key).digest()

    return hash == code