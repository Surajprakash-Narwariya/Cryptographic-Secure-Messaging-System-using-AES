from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os

# AES CBC requires 16-byte blocks, so the IV and key size are 16 bytes.
BLOCK_SIZE = 16

# Key derivation function to generate a strong key from a password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key length
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt function using AES-CBC mode
def encrypt(message: str, password: str) -> tuple:
    # Generate a random salt and IV
    salt = os.urandom(BLOCK_SIZE)
    iv = os.urandom(BLOCK_SIZE)
    
    # Derive the encryption key from the password
    key = derive_key(password, salt)
    
    # Pad the message to be a multiple of BLOCK_SIZE
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    
    # Set up AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the padded message
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return salt, iv, ciphertext

# Decrypt function using AES-CBC mode
def decrypt(salt: bytes, iv: bytes, ciphertext: bytes, password: str) -> str:
    # Derive the decryption key from the password
    key = derive_key(password, salt)
    
    # Set up AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt and unpad the message
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_data) + unpadder.finalize()
    
    return message.decode()

# Example usage
if __name__ == "__main__":
    message = "This is a secret message"
    password = "strong_password"

    # Encrypt the message
    salt, iv, ciphertext = encrypt(message, password)
    print("Ciphertext:", ciphertext)

    # Decrypt the message
    decrypted_message = decrypt(salt, iv, ciphertext, password)
    print("Decrypted Message:", decrypted_message)