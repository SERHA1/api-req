import base64
import json
from Crypto.Cipher import AES

# Secret key for encryption
SECRET_KEY = b'940e357e181dbb8ac82e3b8ec9100746'

# Function to pad data to ensure it is a multiple of 16 bytes (PKCS#7 padding scheme)
def pad(data):
    block_size = 16
    padding_needed = block_size - len(data) % block_size
    padding = chr(padding_needed) * padding_needed
    return data + padding

# Function to unpad the decrypted data (PKCS#7 padding scheme)
def unpad(data):
    padding_length = data[-1]  # Get the padding length (last byte of decrypted data)
    return data[:-padding_length]  # Remove the padding bytes

# Function to encrypt data using AES
def encrypt_data(data, secret_key):
    cipher = AES.new(secret_key, AES.MODE_CBC)
    iv = cipher.iv  # Automatically generate a random IV
    padded_data = pad(data)  # Pad the data to ensure proper AES block size
    
    encrypted_data = cipher.encrypt(padded_data.encode())
    encrypted_data_with_iv = base64.urlsafe_b64encode(iv + encrypted_data).decode('utf-8')  # Combine IV and encrypted data and encode
    return encrypted_data_with_iv

# Function to decrypt data using AES
def decrypt_data(encrypted_data, secret_key):
    encrypted_bytes = base64.urlsafe_b64decode(encrypted_data)
    iv = encrypted_bytes[:16]  # Extract IV (first 16 bytes)
    encrypted_data = encrypted_bytes[16:]  # Extract the actual encrypted data
    
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    
    # Unpad the decrypted data
    return unpad(decrypted_data).decode('utf-8')  # Ensure it's correctly decoded after unpadding

# Test Data
data = {"userId": 5405777, "amount": "500"}

# Convert data to JSON string before encryption
data_json = json.dumps(data)

# Encrypt the data
encrypted_data = encrypt_data(data_json, SECRET_KEY)
print(f"Encrypted data: {encrypted_data}")

# Decrypt the data
decrypted_data = decrypt_data(encrypted_data, SECRET_KEY)
print(f"Decrypted data: {decrypted_data}")

# Check if the decrypted data matches the original data
if decrypted_data == data_json:
    print("Test passed: Decrypted data matches the original data.")
else:
    print("Test failed: Decrypted data does not match the original data.")
