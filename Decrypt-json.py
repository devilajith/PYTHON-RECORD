from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
import json
import os

def decrypt(encrypted_text, secret_key):
    # Split the IV and the encrypted text
    iv_hex, encrypted_message_hex = encrypted_text.split(':')
    iv = bytes.fromhex(iv_hex)
    encrypted_message = bytes.fromhex(encrypted_message_hex)

    # Derive the key using scrypt
    key = scrypt(secret_key, b'salt', 32, N=2**14, r=8, p=1)

    # Create the cipher object and decrypt the data
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(encrypted_message)

    # Remove padding
    padding_length = decrypted_message[-1]
    decrypted_message = decrypted_message[:-padding_length]

    return decrypted_message.decode('utf-8')

def main():
    # Prompt the user for the encrypted JSON file path
    encrypted_file_path = input("Enter the path to the encrypted JSON file: ")
    
    # Prompt the user for the secret key
    secret_key = input("Enter your secret key: ")
    
    # Read the encrypted file
    with open(encrypted_file_path, 'r') as file:
        encrypted_data = file.read().strip()
    
    # Decrypt the data
    decrypted_data = decrypt(encrypted_data, secret_key)
    
    # Parse the decrypted JSON
    json_data = json.loads(decrypted_data)
    
    # Prompt the user for the output decrypted JSON file path
    decrypted_file_path = input("Enter the path to save the decrypted JSON file: ")
    
    # Save the decrypted JSON data to a new file
    os.makedirs(os.path.dirname(decrypted_file_path), exist_ok=True)
    with open(decrypted_file_path, 'w') as file:
        json.dump(json_data, file, indent=4)
    
    print(f"Decrypted data has been saved to {decrypted_file_path}")

if __name__ == '__main__':
    main()
