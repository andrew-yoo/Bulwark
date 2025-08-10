import base64
from argon2 import PasswordHasher

# Settings
argon_time_cost = [4, 4, 8]
argon_memory_cost = [65_536, 1_048_576, 2_097_152]
argon_parallelism = [4, 4, 8]
argon_encoding = 'utf-8'

def derive_key(hash_length: int, password: bytes, argon_salt: bytes, mode: int) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Use Argon2 to derive a key from a password.

    Args:
        hash_length (int): The length of the hashed key, in bytes.
        password (bytes): The password to hash.
        argon_salt (bytes): The salt used for hashing.
        mode (int): 0 for light, 1 for normal, 2 for overkill.

    Returns:
        tuple: A tuple containing four byte strings derived from the hash.
    """
    
    if mode not in [0, 1, 2]:
        raise ValueError("Mode incorrectly defined. Must be 0 (light), 1 (normal), or 2 (overkill).")

    # Initialize PasswordHasher with appropriate parameters
    ph = PasswordHasher(
        time_cost=argon_time_cost[mode],
        memory_cost=argon_memory_cost[mode],
        parallelism=argon_parallelism[mode],
        hash_len=hash_length,
        encoding=argon_encoding
    )
    
    # Generate the hash
    hash_string = ph.hash(password=password, salt=argon_salt)
    
    encoded_hash = hash_string.split('$')[-1]
    
    padding_needed = len(encoded_hash) % 4
    if padding_needed:
        encoded_hash += '=' * (4 - padding_needed)


    # Decode the hash
    hash = base64.b64decode(encoded_hash)

    # Split the hash based on the mode
    if mode in [0, 1]:
        hash1 = hash[::2]
        hash2 = hash[1::2]
        hash3 = b''  # Placeholder for future use
        hash4 = b''  # Placeholder for future use
    else:
        hash1 = hash[::4]
        hash2 = hash[1::4]
        hash3 = hash[2::4]
        hash4 = hash[3::4]

    return hash1, hash2, hash3, hash4
