from cryptography.fernet import Fernet
import base64

# Generates and returns a key
def keyGen():
    key = Fernet.generate_key()
    return key

# Takes a message and a key and encrypts it. Prints out original message, key and encrypted message
def encryptWKey():
    message = input("Enter your message: ")
    key = input("Enter your encryption key: ")
    try:
        key_bytes = base64.urlsafe_b64encode(key.encode())
        cipher = Fernet(key_bytes)
        encrypted_message = cipher.encrypt(message.encode())
        print(f"Original message: {message}")
        print(f"Key: {key}")
        print(f"Encrypted message: {base64.urlsafe_b64encode(encrypted_message).decode()}")
    except ValueError:
        print("Invalid key format. Key must be 32 URL-safe base64-encoded bytes")

# Takes a message and generates a key and encrypts it. Prints out original message, key and encrypted message
def encryptWOKey():
    message = input("Enter your message: ")
    key = keyGen()
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    print(f"Original message: {message}")
    print(f"Key: {key}")
    print(f"Encrypted message: {encrypted_message}")

# Takes a message and a key and decrypts it. Prints out original message, key and decrypted message
def decryptWKey():
    message = input("Enter your message: ")
    key = input("Enter your decryption key: ")
    try:
        key_bytes = base64.urlsafe_b64decode(key.encode())
        cipher = Fernet(key_bytes)
        message_bytes = base64.urlsafe_b64decode(message.encode())
        decrypted_message = cipher.decrypt(message_bytes).decode()
        print(f"Original message: {message}")
        print(f"Key: {key}")
        print(f"decrypted message: {decrypted_message}")
    except ValueError:
        print("Invalid key format. Key must be 32 URL-safe base64-encoded bytes")

if __name__ == "__main__":
    choice = input("Choose your option (Please select 1, 2, 3 or 4)\n1. Generate key\n2. Encrypt w/key\n3. Encrypt wo/key\n4. Decrypt w/key\n")
    if choice == "1":
        print(f"Key: {keyGen()}")
    elif choice == "2":
        encryptWKey()
    elif choice == "3":
        encryptWOKey()
    elif choice == "4":
        decryptWKey()
    else:
        print("Not a valid choice, please try again")
