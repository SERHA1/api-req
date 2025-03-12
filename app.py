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
        used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
""")
conn.commit()

# Function to check if the party_id is already used
def is_party_id_used(party_id):
    cur.execute("SELECT 1 FROM used_party_ids WHERE party_id = %s", (str(party_id),))  # Cast party_id to string
    return cur.fetchone() is not None

# Function to store the party_id
def store_party_id(party_id):
    cur.execute("INSERT INTO used_party_ids (party_id) VALUES (%s) ON CONFLICT DO NOTHING", (str(party_id),))
    conn.commit()

# Function to unpad the decrypted data (PKCS7 padding)
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


@app.route('/webhook', methods=['GET'])
def webhook():
    encrypted_data = request.args.get("data")

    if not encrypted_data:
        return jsonify({"status": "error", "message": "Missing encrypted data"}), 400

    try:
        decrypted_data = decrypt_data(encrypted_data, SECRET_KEY)
    except Exception as e:
        return jsonify({"status": "error", "message": f"Decryption failed: {str(e)}"}), 400

    party_id = decrypted_data["userId"]  # Assuming partyId is in "userId"

    # Start a database transaction
    try:
        # Check if the party_id is already used
        if is_party_id_used(party_id):
            return  generate_html_response("Bonus daha önce kullanılmış.", "https://www.bhspwa41.com/tr/")
 # Forbidden

        # Store the party_id before processing
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

        # Send the request to the API
        response = requests.post("https://ps-secundus.gmntc.com/ips/bonus/trigger", json=json_body, headers=headers)

        # Return the API response
        return jsonify({"status": "success", "message": "Request sent to API", "api_response": response.json()})

    except Exception as e:
        conn.rollback()  # Rollback the transaction in case of any failure
         return generate_html_response("Hata Oluştu", "https://www.bhspwa41.com/tr/")

def generate_html_response(message, redirect_url):
    return f"""
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Yönlendiriliyor...</title>
        <script>
            let countdown = 5;
            function updateCountdown() {{
                document.getElementById('counter').innerText = countdown;
                if (countdown === 0) {{
                    window.location.href = "{redirect_url}";
                }} else {{
                    countdown--;
                    setTimeout(updateCountdown, 1000);
                }}
            }}
            window.onload = updateCountdown;
        </script>
        <style>
            body {{
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                flex-direction: column;
                font-family: Arial, sans-serif;
            }}
            .circle {{
                width: 80px;
                height: 80px;
                border-radius: 50%;
                background-color: #f44336;
                color: white;
                display: flex;
                justify-content: center;
                align-items: center;
                font-size: 24px;
                font-weight: bold;
                margin-top: 20px;
            }}
        </style>
    </head>
    <body>
        <h2>{message}</h2>
        <div class="circle" id="counter">5</div>
    </body>
    </html>
    """
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
