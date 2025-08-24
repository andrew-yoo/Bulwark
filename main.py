import argparse
import tomllib
import safe

def main():
    settings = parse()
    if settings['action'] == 'encrypt':
        encrypt(settings)
    elif settings['action'] == 'decrypt':
        decrypt(settings)

def parse():
    """
    Parse command line arguments and execute the appropriate function.
    Returns:
        dict: file path, encryption/decryption, mode
    """
    settings ={}

    parser = argparse.ArgumentParser()
    parser.add_argument("file_path", help="Enter the file path of the file to encrypt or decrypt.")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the file")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt the file")
    parser.add_argument("-l", "--light", action="store_true", help="Use light mode")
    parser.add_argument("-o", "--overkill", action="store_true", help="Use overkill mode")
    args = parser.parse_args()

    settings['file_path'] = args.file_path

    if args.encrypt:
        settings['action'] = 'encrypt'
    else:
        settings['action'] = 'decrypt'
    
    if args.light:
        settings['mode'] = 0
    elif args.overkill:
        settings['mode'] = 2
    else:
        settings['mode'] = 1

    return settings

def encrypt(settings):
    """
    """
    with open(settings['file_path'], 'rb') as file:
        plaintext = file.read()
    password = input('Password: ').encode()

    with open("config.toml", mode="rb") as toml_file:
        config = tomllib.load(toml_file)

    safe.write_file(file_name=settings['file_path'],
                    magic_number_string=config['magic_number']['magic_number_string'],
                    version_code_int=config['version']['version_string'],
                    password=password,
                    plaintext=plaintext,
                    mode=settings['mode'])

def decrypt(settings):
    """
    """
    unpacked = safe.read_file(settings['file_path'])

    password = input("Password: ").encode()

    data = safe.unlock_safe(password=password,
                                argon_salt=unpacked[0], xchacha_nonce=unpacked[1], camellia_nonce=unpacked[2], aes_nonce=unpacked[3], ciphertext=unpacked[4], 
                                mode=settings['mode'])

    with open(f'{(settings['file_path']).replace('.blwk', '')}', 'wb') as file:
        file.write(data)

if __name__ == "__main__":
    main()