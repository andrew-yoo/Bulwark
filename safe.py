import secrets
import tomllib

import password_hashing
import encryption
import authentication

# The functions write_file and unlock_safe are the only ones that need to be called.
# TODO: make this less confusing


def lock_safe(
    password: bytes, plaintext: bytes, mode: int
) -> tuple[bytes, bytes, bytes, bytes, bytes, bytes]:
    """
    Generates keys and encrypts data.

    Args:
        password (bytes): The user-provided password
        plaintext (bytes): The plaintext to encrypt
        mode (int): 0-light, 1-normal, 2-overkill

    Returns:
        tuple: MAC Key, Argon2 Salt, XChaCha Nonce, Camellia Nonce, AES Nonce, Ciphertext
    """

    argon_salt = secrets.token_bytes(32)

    if mode == 0:
        # Hash length = 64: 32 bytes for xchacha, 32 bytes for MAC
        keystring = password_hashing.derive_key(
            hash_length=64, password=password, argon_salt=argon_salt, mode=0
        )
        mac_key = keystring[0]
        xchacha_key = keystring[1]
        camellia_key = keystring[2]  # Empty bytes
        aes_key = keystring[3]  # Empty bytes

        encrypted = encryption.xchacha_encrypt(
            xchacha_key=xchacha_key, plaintext=plaintext
        )
        xchacha_nonce = encrypted[0]
        camellia_nonce = bytes(16)  # Empty Padding
        aes_nonce = bytes(16)  # Empty Padding
        ciphertext = encrypted[1]

    elif mode == 1:
        # Hash length = 64: 32 bytes for xchacha, 32 bytes for MAC
        keystring = password_hashing.derive_key(
            hash_length=64, password=password, argon_salt=argon_salt, mode=1
        )
        mac_key = keystring[0]
        xchacha_key = keystring[1]
        camellia_key = keystring[2]  # Empty bytes
        aes_key = keystring[3]  # Empty bytes

        encrypted = encryption.xchacha_encrypt(
            xchacha_key=xchacha_key, plaintext=plaintext
        )
        xchacha_nonce = encrypted[0]
        camellia_nonce = bytes(16)  # Empty Padding
        aes_nonce = bytes(16)  # Empty Padding
        ciphertext = encrypted[1]

    elif mode == 2:
        # Hash length = 128: 32 bytes for xchacha, 32 bytes for camellia, 32 bytes for aes, 32 bytes for MAC
        keystring = password_hashing.derive_key(
            hash_length=128, password=password, argon_salt=argon_salt, mode=2
        )
        mac_key = keystring[0]
        xchacha_key = keystring[1]
        camellia_key = keystring[2]
        aes_key = keystring[3]

        encrypted = encryption.xchacha_camellia_aes_encrypt(
            xchacha_key=xchacha_key,
            camellia_key=camellia_key,
            aes_key=aes_key,
            plaintext=plaintext,
        )
        xchacha_nonce = encrypted[0]
        camellia_nonce = encrypted[1]
        aes_nonce = encrypted[2]
        ciphertext = encrypted[3]

    else:
        raise ValueError("Mode incorrectly defined")

    return mac_key, argon_salt, xchacha_nonce, camellia_nonce, aes_nonce, ciphertext


def unlock_safe(password: bytes, file_path: str):
    """
    Decrypts the ciphertext.

    Args:
        password (bytes): The user-supplied password
        file_path (str): The file path of the ciphertext

    Returns:
        bytes: Decrypted plaintext
    """

    (
        magic_number,
        version,
        mac,
        mode,
        argon_salt,
        xchacha_nonce,
        camellia_nonce,
        aes_nonce,
        ciphertext,
    ) = read_file(file_path)

    # Make sure the magic number and version are correct
    with open("config.toml", mode="rb") as toml_file:
        config = tomllib.load(toml_file)
    if magic_number != config["magic_number"]["magic_number_string"].encode():
        raise Exception("Incorrect magic number")
    elif version != config["version"]["version_string"].to_bytes(2, "little"):
        raise Exception("Incorrect version")

    # Generate the Mac to check against the provided one
    if (mode == 0) or (mode == 1):
        mac_key = password_hashing.derive_key(64, password, argon_salt, mode)[0]
    else:
        mac_key = password_hashing.derive_key(128, password, argon_salt, mode)[0]

    # Check to see if the MACs match
    if not authentication.check_mac(code=mac, mac_key=mac_key, message=ciphertext):
        raise Exception("Incorrect MAC")

    if mode == 0:
        keystring = password_hashing.derive_key(
            hash_length=64, password=password, argon_salt=argon_salt, mode=0
        )
        xchacha_key = keystring[1]
        camellia_key = keystring[2]  # Empty bytes
        aes_key = keystring[3]  # Empty bytes

        decrypted = encryption.xchacha_decrypt(
            xchacha_key=xchacha_key, xchacha_nonce=xchacha_nonce, ciphertext=ciphertext
        )

    elif mode == 1:
        keystring = password_hashing.derive_key(
            hash_length=64, password=password, argon_salt=argon_salt, mode=1
        )
        xchacha_key = keystring[1]
        camellia_key = keystring[2]  # empty bytes
        aes_key = keystring[3]  # Empty bytes

        decrypted = encryption.xchacha_decrypt(
            xchacha_key=xchacha_key, xchacha_nonce=xchacha_nonce, ciphertext=ciphertext
        )

    elif mode == 2:
        keystring = password_hashing.derive_key(
            hash_length=128, password=password, argon_salt=argon_salt, mode=2
        )
        xchacha_key = keystring[1]
        camellia_key = keystring[2]
        aes_key = keystring[3]

        decrypted = encryption.xchacha_camellia_aes_decrypt(
            xchacha_key=xchacha_key,
            xchacha_nonce=xchacha_nonce,
            camellia_key=camellia_key,
            camellia_nonce=camellia_nonce,
            aes_key=aes_key,
            aes_nonce=aes_nonce,
            ciphertext=ciphertext,
        )

    else:
        raise ValueError("Mode incorrectly defined.")

    return decrypted


def write_file(
    file_name: str,
    magic_number_string: str,
    version_code_int: int,
    password: bytes,
    plaintext: bytes,
    mode: int,
):
    """ """
    locked_safe = lock_safe(password=password, plaintext=plaintext, mode=mode)

    mac = authentication.mac(mac_key=locked_safe[0], message=locked_safe[5])
    argon_salt = locked_safe[1]
    xchacha_nonce = locked_safe[2]
    camellia_nonce = locked_safe[3]
    aes_nonce = locked_safe[4]
    ciphertext = locked_safe[5]

    magic_number = magic_number_string.encode()
    version_code = version_code_int.to_bytes(2, byteorder="little")

    mode_bytes = mode.to_bytes()

    # Not including magic number, version code, or MAC
    # file_contents = mode_bytes + bytes(1) + bytes(8) + argon_salt + xchacha_nonce + camellia_nonce + aes_nonce + ciphertext

    with open(f"{file_name}.blwk", "wb") as new_file:
        new_file.write(magic_number)  # Magic Number
        new_file.write(version_code)  # Version Code
        new_file.write(mac)  # Message Authentication Code
        new_file.write(mode_bytes)  # Light/Normal/Overkill
        new_file.write(bytes(1))  # Empty for now
        new_file.write(bytes(8))  # Empty for now
        new_file.write(argon_salt)  # Salt for Argon2 KDF
        new_file.write(xchacha_nonce)  # Salt for XChaCha
        new_file.write(camellia_nonce)  # Salt for Camellia or 16 null bytes
        new_file.write(aes_nonce)  # Salt for AES or 16 null bytes
        new_file.write(ciphertext)


def read_file(file_path: str):
    """
    Args:
        file_path (str): The file path of the file to read

    Returns:
        tuple: Magic number, Version, MAC, Mode, Argon salt, XChaCha nonce, Camellia nonce, AES nonce, Ciphertext
    """
    try:
        with open(file_path, "rb") as open_file:
            magic_number = open_file.read(4)
            version = open_file.read(2)
            mac = open_file.read(32)
            mode = int.from_bytes(open_file.read(1))
            _ = open_file.read(1)
            _ = open_file.read(8)
            argon_salt = open_file.read(32)
            xchacha_nonce = open_file.read(24)
            camellia_nonce = open_file.read(16)
            aes_nonce = open_file.read(16)
            ciphertext = open_file.read()

    except FileNotFoundError:
        print("File not found")
        exit(1)

    return (
        magic_number,
        version,
        mac,
        mode,
        argon_salt,
        xchacha_nonce,
        camellia_nonce,
        aes_nonce,
        ciphertext,
    )
