from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def encrypt_message(key, message):
    key = key[:16]
    key = pad(key.encode(), AES.block_size)

    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message.encode(), AES.block_size)

    encrypted_message = cipher.encrypt(padded_message)

    return encrypted_message

def decrypt_message(key, encrypted_message):
    key = key[:16]
    key = pad(key.encode(), AES.block_size)

    cipher = AES.new(key, AES.MODE_ECB)

    decrypted_message = cipher.decrypt(encrypted_message)

    decrypted_message = unpad(decrypted_message, AES.block_size)

    return decrypted_message.decode()


import argparse

def main():
    # Create the top-level parser
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")

    # Create parser for "encrypt" command
    encrypt_parser = subparsers.add_parser('encrypt')
    encrypt_parser.add_argument('key', help='encryption key')
    encrypt_parser.add_argument('message', help='message to encrypt')

    # Create parser for "decrypt" command
    decrypt_parser = subparsers.add_parser('decrypt')
    decrypt_parser.add_argument('key', help='encryption key')
    decrypt_parser.add_argument('encrypted_message', help='message to decrypt', type=bytes.fromhex)

    args = parser.parse_args()

    if args.command == "encrypt":
        encrypted_message = encrypt_message(args.key, args.message)
        print(encrypted_message.hex())
    elif args.command == "decrypt":
        decrypted_message = decrypt_message(args.key, args.encrypted_message)
        print(decrypted_message)

if __name__ == "__main__":
    main()
