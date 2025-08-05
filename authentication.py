from blake3 import blake3

def mac(mac_key: bytes, message: bytes) -> bytes:
    """
    Use keyed Blake3 as a MAC.

    Args:
        key (bytes): 
        data (bytes): 
    """
    if len(mac_key) != 32:
        raise ValueError("MAC key must be 32 bytes.")
    
    return blake3(message, key=mac_key).digest()

def check_mac(code: bytes, mac_key:bytes, message: bytes):
    hash = blake3(message, key=mac_key).digest()

    return hash == code