import secrets
from argon2 import PasswordHasher

# Settings
argon_time_cost =   [4, 4, 8]
argon_memory_cost = [65_536, 1_048_576, 2_097_152]
argon_parallelism = [4, 4, 8]
argon_hash_length = [64, 64, 128] #
argon_encoding = 'utf-8'

def derive_key(hash_length: int, password: bytes, salt_length: int, mode: int) -> str:
    """
    Use Argon2 to derive a key from a password.
    
    Args:
        hash_length (int): The length of the hashed key, in bytes
        password (bytes): The password
        salt_length (int): The length of the salt, in bytes
        mode (int): 0-light, 1-normal, 2-overkill

    Returns:
        str: The argon salt along with parameters
    """

    # Light Mode
    if mode == 0:
        argon_salt = secrets.token_bytes(salt_length)
        ph = PasswordHasher(time_cost=argon_time_cost[0], memory_cost=argon_memory_cost[0], parallelism=argon_parallelism[0], hash_len=argon_hash_length[0], salt_len=salt_length, encoding=argon_encoding)
        hash = ph.hash(password=password, salt=argon_salt)
    
    # Normal Mode
    elif mode == 1:
        argon_salt = secrets.token_bytes(salt_length)
        ph = PasswordHasher(time_cost=argon_time_cost[1], memory_cost=argon_memory_cost[1], parallelism=argon_parallelism[1], hash_len=argon_hash_length[1], salt_len=salt_length, encoding=argon_encoding)
        hash = ph.hash(password=password, salt=argon_salt)

    # Overkill Mode
    elif mode == 2:
        argon_salt = secrets.token_bytes(salt_length)
        ph = PasswordHasher(time_cost=argon_time_cost[2], memory_cost=argon_memory_cost[2], parallelism=argon_parallelism[2], hash_len=argon_hash_length[2], salt_len=salt_length, encoding=argon_encoding)
        hash = ph.hash(password=password, salt=argon_salt)

    else:
        raise ValueError("Mode incorrectly defined.")

    return hash