import os
import json
import time
import base64
import requests
import psycopg2  # PostgreSQL connector
from Crypto.Cipher import AES
import hashlib
import hmac
from flask import Flask, request, jsonify
from urllib.parse import urlparse  # Make sure to import urlparse


app = Flask(__name__)

# Load environment variables
SECRET_KEY = os.getenv("SECRET_KEY", "fallback_key").encode()
CHECKSUM_SECRET_KEY = os.getenv("CHECKSUM_SECRET_KEY", "fallback_checksum_key").encode()
DATABASE_URL = os.getenv("DATABASE_URL")  # Render PostgreSQL database

if DATABASE_URL is None:
    raise ValueError("DATABASE_URL is not set in the environment variables")

# Parse the DATABASE_URL to extract the components
url = urlparse(DATABASE_URL)

# Connect to the PostgreSQL database
try:
    conn = psycopg2.connect(
        database=url.path[1:],  # Extract the database name from the URL path (remove leading '/')
        user=url.username,
        password=url.password,
        host=url.hostname,
        port=url.port
    )
    print("Connected to the PostgreSQL database successfully!")
except Exception as e:
    print(f"Failed to connect to the database: {e}")

# Create a cursor to interact with the database
cur = conn.cursor()

# Ensure table exists
cur.execute("""
    CREATE TABLE IF NOT EXISTS used_party_ids (
        id SERIAL PRIMARY KEY,
        party_id TEXT UNIQUE NOT NULL,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
""")
conn.commit()

# Function to check if partyId already exists
def is_party_id_used(party_id):
    cur.execute("SELECT 1 FROM used_party_ids WHERE party_id = %s", (party_id,))
    return cur.fetchone() is not None

# Function to store partyId
def store_party_id(party_id):
    cur.execute("INSERT INTO used_party_ids (party_id) VALUES (%s) ON CONFLICT DO NOTHING", (party_id,))
    conn.commit()
    
def unpad(data):
    padding_length = data[-1]  # Get the padding length (last byte of decrypted data)
    return data[:-padding_length]  # Remove the padding bytes

# Function to decrypt data
def decrypt_data(encrypted_data, secret_key):
    try:
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data)
        iv = encrypted_bytes[:16]  # Extract IV (first 16 bytes)
        encrypted_data = encrypted_bytes[16:]  # Extract the actual encrypted data
        
        # Decrypt data using AES
        cipher = AES.new(secret_key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # Unpad the decrypted data and decode it as a string
        decrypted_string = unpad(decrypted_data).decode('utf-8')  # Ensure it's correctly decoded after unpadding
        
        # Convert the decrypted string to a dictionary (assuming it's a valid JSON string)
        return json.loads(decrypted_string)
    except Exception as e:
        # Debugging output to check what's wrong
        print(f"Decryption error: {e}")
        return None

@app.route('/webhook', methods=['GET'])
def webhook():
    encrypted_data = request.args.get("data")

    if not encrypted_data:
        return jsonify({"status": "error", "message": "Missing encrypted data"}), 400

    # Log the encrypted data to check what is being received
    print(f"Received encrypted data: {encrypted_data}")
    
    try:
        decrypted_data = decrypt_data(encrypted_data, SECRET_KEY)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Decryption failed: {str(e)}"}), 400

    party_id = decrypted_data["userId"]  # The key to track usage

    # Check if partyId is already used
    if is_party_id_used(party_id):
        return jsonify({"status": "error", "message": "partyId already used, API request not sent"}), 403  # Forbidden

    # Store the partyId in the database
    store_party_id(party_id)

    # Prepare the API request
    json_body = {
        "partyId": party_id,
        "brandId": 23,
        "bonusPlanID": 14747,
        "amount": decrypted_data["amount"],
        "reason": "test1",
        "timestamp": int(time.time() * 1000)
    }

    checksum = hmac.new(CHECKSUM_SECRET_KEY, f"{json_body['partyId']},{json_body['brandId']},{json_body['bonusPlanID']},{json_body['amount']},{json_body['reason']},{json_body['timestamp']}".encode(), hashlib.sha512)
    
    headers = {
        'Checksum-Fields': 'partyId,brandId,bonusPlanID,amount,reason,timestamp',
        'Checksum': base64.b64encode(checksum.digest()).decode('utf-8')
    }

    response = requests.post("https://ps-secundus.gmntc.com/ips/bonus/trigger", json=json_body, headers=headers)

    return jsonify({"status": "success", "message": "Request sent to API", "api_response": response.json()})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
