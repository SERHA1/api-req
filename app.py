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

app = Flask(__name__)

# Load environment variables
SECRET_KEY = os.getenv("SECRET_KEY", "fallback_key").encode()
CHECKSUM_SECRET_KEY = os.getenv("CHECKSUM_SECRET_KEY", "fallback_checksum_key").encode()
DATABASE_URL = os.getenv("DATABASE_URL")  # Render PostgreSQL database

# Connect to Render PostgreSQL
conn = psycopg2.connect(DATABASE_URL)
cur = conn.cursor()

# Ensure table exists
cur.execute("""
    CREATE TABLE IF NOT EXISTS used_keys (
        id SERIAL PRIMARY KEY,
        key TEXT UNIQUE NOT NULL,
        used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
""")
conn.commit()

# Function to check if key exists
def is_key_used(key):
    cur.execute("SELECT 1 FROM used_keys WHERE key = %s", (key,))
    return cur.fetchone() is not None

# Function to store used key
def store_key(key):
    cur.execute("INSERT INTO used_keys (key) VALUES (%s) ON CONFLICT DO NOTHING", (key,))
    conn.commit()

# Function to decrypt data
def decrypt_data(encrypted_data, secret_key):
    encrypted_bytes = base64.urlsafe_b64decode(encrypted_data)
    iv = encrypted_bytes[:16]
    encrypted_data = encrypted_bytes[16:]

    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)

    return json.loads(decrypted_data.decode('utf-8').rstrip("\x00"))

@app.route('/webhook', methods=['GET'])
def webhook():
    encrypted_data = request.args.get("data")

    if not encrypted_data:
        return jsonify({"status": "error", "message": "Missing encrypted data"}), 400

    try:
        decrypted_data = decrypt_data(encrypted_data, SECRET_KEY)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Decryption failed: {str(e)}"}), 400

    user_id = decrypted_data["userId"]  # The key to track usage

    # Check if key is already used
    if is_key_used(user_id):
        return jsonify({"status": "error", "message": "Key already used"}), 403  # Forbidden

    # Store the key before processing
    store_key(user_id)

    # Prepare the API request
    json_body = {
        "partyId": user_id,
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
