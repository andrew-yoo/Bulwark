import argparse
import tomllib

import safe

with open("config.toml", mode="rb") as toml_file:
    configuration = tomllib.load(toml_file)

magic_number_string = configuration["magic_number"]["magic_number_string"]
version_code = configuration["version"]["version_string"]

parser = argparse.ArgumentParser()
parser.add_argument("file_path", help="Enter the file path of the file to encrypt or decrypt.")
parser.add_argument("-e", "--encrypt", action="store_true")
parser.add_argument("-d", "--decrypt", action="store_true")

args = parser.parse_args()

if args.encrypt:

    with open(args.file_path, 'rb') as file:
        plaintext = file.read()

    # ONLY USING NORMAL MODE FOR NOW

    password = input("Password: ")

    safe.write_file(file_name=args.file_path, magic_number_string=magic_number_string, version_code_int=version_code, password=password.encode(), plaintext=plaintext, mode=1)

if args.decrypt:
    
    unpacked = safe.read_file(args.file_path)

    password = input("Password: ").encode()

    # ONLY NORMAL MODE FOR NOW

    data = safe.unlock_safe(password=password, argon_salt=unpacked[0], xchacha_nonce=unpacked[1], camellia_nonce=unpacked[2], aes_nonce=unpacked[3], ciphertext=unpacked[4], mode=1)

    with open(f'{(args.file_path).replace('.blwk', '')}', 'wb') as file:
        file.write(data)