from flask import Flask, request, jsonify
import base64
import json
import time
from Crypto.Cipher import AES
import hashlib
import hmac
import requests

app = Flask(__name__)

# Secret key for encryption/decryption
SECRET_KEY = b'940e357e181dbb8ac82e3b8ec9100746'

# Function to unpad the decrypted data (PKCS#7 padding scheme)
def unpad(data):
    return data[:-ord(data[-1])]

# Function to decrypt the encrypted data
def decrypt_data(encrypted_data):
    try:
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data)
        iv = encrypted_bytes[:16]  # Extract IV
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
        
        decrypted_bytes = cipher.decrypt(encrypted_bytes[16:])
        decrypted_data = json.loads(unpad(decrypted_bytes).decode())
        return decrypted_data
    except Exception as e:
        return {"error": str(e)}

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

    # Decrypt the data from the URL
    decrypted_data = decrypt_data(encrypted_data)

    if "error" in decrypted_data:
        return jsonify({"status": "error", "message": "Decryption failed"}), 400

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
    checksum = create_checksum(json_body, SECRET_KEY)
    
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

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
