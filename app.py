import base64
import json
import time
import requests  # Add this import to fix the error
from Crypto.Cipher import AES
import hashlib
import hmac
from flask import Flask, request, jsonify

app = Flask(__name__)

# Secret key for encryption/decryption
SECRET_KEY = b'940e357e181dbb8ac82e3b8ec9100746'
CHECKSUM_SECRET_KEY = b'2799b549-16ad-4702-8910-1316e6b1389e'  # Use checksum secret key

# Function to pad the data (PKCS#7 padding scheme)
def pad(data):
    block_size = 16
    padding_needed = block_size - len(data) % block_size
    padding = chr(padding_needed) * padding_needed
    return data + padding

# Function to unpad the decrypted data (PKCS#7 padding scheme)
def unpad(data):
    padding_length = data[-1]  # Get the padding length (last byte of decrypted data)
    return data[:-padding_length]  # Remove the padding bytes

# Function to decrypt the encrypted data
def decrypt_data(encrypted_data, secret_key):
    encrypted_bytes = base64.urlsafe_b64decode(encrypted_data)
    iv = encrypted_bytes[:16]  # Extract IV (first 16 bytes)
    encrypted_data = encrypted_bytes[16:]  # Extract the actual encrypted data
    
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    
    # Unpad the decrypted data and decode it as a string
    decrypted_string = unpad(decrypted_data).decode('utf-8')  # Ensure it's correctly decoded after unpadding
    
    # Convert the decrypted string to a dictionary (assuming it's a valid JSON string)
    return json.loads(decrypted_string)

# Function to create checksum (HMAC-SHA512)
def create_checksum(data, secret_key):
    input_string = f"{data['partyId']},{data['brandId']},{data['bonusPlanID']},{data['amount']},{data['reason']},{data['timestamp']}"
    hash = hmac.new(secret_key, input_string.encode(), hashlib.sha512)
    checksum = base64.b64encode(hash.digest()).decode('utf-8')
    return checksum

@app.route('/webhook', methods=['GET'])
def webhook():
    """Webhook endpoint to receive encrypted data and send API request."""
    encrypted_data = request.args.get("data")
    
    if not encrypted_data:
        return jsonify({"status": "error", "message": "Missing encrypted data"}), 400

    # Decrypt the data from the URL using the secret key
    try:
        decrypted_data = decrypt_data(encrypted_data, SECRET_KEY)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Decryption failed: {str(e)}"}), 400

    # Create the JSON body with the decrypted data
    json_body = {
        "partyId": decrypted_data["userId"],  # Get partyId from decrypted data
        "brandId": 23,  # Fixed value
        "bonusPlanID": 14747,  # Fixed value
        "amount": decrypted_data["amount"],  # Get amount from decrypted data
        "reason": "test1",  # Fixed value
        "timestamp": int(time.time() * 1000)  # Current timestamp in milliseconds
    }

    # Create checksum header
    checksum = create_checksum(json_body, CHECKSUM_SECRET_KEY)
    
    # Set headers
    headers = {
        'Checksum-Fields': 'partyId,brandId,bonusPlanID,amount,reason,timestamp',
        'Checksum': checksum
    }

    # API URL
    api_url = "https://ps-secundus.gmntc.com/ips/bonus/trigger"
    
    # Send the POST request to the API
    response = requests.post(api_url, json=json_body, headers=headers)

    # Return the response from the API
    return jsonify({
        "status": "success",
        "message": "Request sent to API",
        "api_response": response.json()
    })

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))  # Render uses PORT env variable
    app.run(host="0.0.0.0", port=port)

