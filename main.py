import argparse
import tomllib
import safe

def main():
    settings = parse()

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

if __name__ == "__main__":
    main()