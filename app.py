import os
import json
import time
import base64
import requests
import psycopg2  # PostgreSQL connector
from Crypto.Cipher import AES
import hashlib
import hmac
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from urllib.parse import urlparse  # Make sure to import urlparse
import secrets
import random


app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a secure secret key
app.config['SESSION_TYPE'] = 'filesystem'  # Use filesystem-based sessions
app.config['SESSION_PERMANENT'] = False  # Make sessions non-permanent
app.config['SESSION_USE_SIGNER'] = True  # Sign the session cookie
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS

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
        used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        game_id INTEGER
    );
""")
conn.commit()

# Add this after the first table creation
cur.execute("""
    CREATE TABLE IF NOT EXISTS game_results (
        id SERIAL PRIMARY KEY,
        party_id TEXT UNIQUE NOT NULL,
        result_type TEXT NOT NULL,
        amount INTEGER,
        bonus_plan_id INTEGER,
        played_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
""")
conn.commit()

# First, add the game_id column to the used_party_ids table
cur.execute("""
    ALTER TABLE used_party_ids 
    ADD COLUMN IF NOT EXISTS game_id INTEGER;
""")
conn.commit()

# Function to check if the party_id is already used
def is_party_id_used(party_id):
    cur.execute("SELECT 1 FROM used_party_ids WHERE party_id = %s", (str(party_id),))  # Cast party_id to string
    return cur.fetchone() is not None

# Update the store_party_id function to accept a game_id parameter
def store_party_id(party_id, game_id=None):
    cur.execute("INSERT INTO used_party_ids (party_id, game_id) VALUES (%s, %s) ON CONFLICT (party_id) DO UPDATE SET game_id = EXCLUDED.game_id", 
                (str(party_id), game_id))
    conn.commit()

# Update the store_game_result function to return the inserted ID
def store_game_result(party_id, result_type, amount=None, bonus_plan_id=None):
    cur.execute(
        """
        INSERT INTO game_results (party_id, result_type, amount, bonus_plan_id) 
        VALUES (%s, %s, %s, %s)
        RETURNING id
        """,
        (str(party_id), result_type, amount, bonus_plan_id)
    )
    result = cur.fetchone()
    conn.commit()
    return result[0] if result else None

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

# Define game segments on server side
GAME_SEGMENTS = [
    {'position': 0, 'type': 'lose', 'text': 'Ödül Kazanamadınız'},
    {'position': 1, 'type': 'win', 'text': 'Win 100TL Bonus', 'amount': 100, 'planId': 14747},
    {'position': 2, 'type': 'lose', 'text': 'Ödül Kazanamadınız'},
    {'position': 3, 'type': 'win', 'text': 'Win 250TL Bonus', 'amount': 250, 'planId': 14747}
]

# Update the WHEEL_SEGMENTS to match the new visual layout
WHEEL_SEGMENTS = [
    {'position': 1, 'type': 'win', 'text': '100TL Ödül Kazandınız', 'amount': 100, 'planId': 14747},
    {'position': 2, 'type': 'win', 'text': '150TL Ödül Kazandınız', 'amount': 150, 'planId': 14747},
    {'position': 3, 'type': 'win', 'text': '250TL Ödül Kazandınız', 'amount': 250, 'planId': 14747},
    {'position': 0, 'type': 'lose', 'text': 'Ödül Kazanamadınız'}
]

@app.route('/webhook', methods=['GET'])
def webhook():
    encrypted_data = request.args.get("data")
    
    if not encrypted_data:
        print("Missing encrypted data")
        return generate_html_response("Invalid request.", "https://www.bhspwa41.com/tr/")

    try:
        decrypted_data = decrypt_data(encrypted_data, SECRET_KEY)
        party_id = decrypted_data["userId"]
        
        # Check if user already played
        if is_party_id_used(party_id):
            print(f"Party ID {party_id} already used")
            return generate_html_response("Bonus daha önce kullanılmış.", "https://www.bhspwa41.com/tr/")
            
        # Store session data for the game
        session['game_token'] = secrets.token_hex(32)
        session['party_id'] = party_id
        session['amount'] = decrypted_data["amount"]
        session['can_play'] = True
        
        print(f"Rendering wheel for party_id: {party_id}")
        return render_template('wheel.html', token=session['game_token'])
        
    except Exception as e:
        print(f"Error in webhook: {str(e)}")
        import traceback
        traceback.print_exc()
        return generate_html_response("Hata Oluştu", "https://www.bhspwa41.com/tr/")

@app.route('/process_game_result', methods=['POST'])
def process_game_result():
    # Verify game token and session
    if not session.get('can_play') or request.json.get('token') != session.get('game_token'):
        return jsonify({
            "message": "Invalid session",
            "redirect_url": "https://www.bhspwa41.com/tr/"
        })

    party_id = session.get('party_id')
    if not party_id:
        return jsonify({
            "message": "Session expired",
            "redirect_url": "https://www.bhspwa41.com/tr/"
        })

    try:
        # Final database check before processing
        if is_party_id_used(party_id):
            return jsonify({
                "message": "Already played",
                "redirect_url": "https://www.bhspwa41.com/tr/"
            })

        result_type = request.json.get('result_type')
        amount = request.json.get('amount')
        bonus_plan_id = request.json.get('planId')

        # Store the game result first
        store_game_result(party_id, result_type, amount, bonus_plan_id)
        
        # Mark as played in the used_party_ids table
        store_party_id(party_id)
        
        # Disable further plays in this session
        session['can_play'] = False

        # If it's a losing result, just return the message
        if result_type == 'lose':
            return jsonify({
                "message": "Sorry No Award",
                "redirect_url": "https://www.bhspwa41.com/tr/"
            })

        # For winning results, trigger the bonus API
        json_body = {
            "partyId": party_id,
            "brandId": 23,
            "bonusPlanID": int(bonus_plan_id),
            "amount": amount,
            "reason": "test1",
            "timestamp": int(time.time() * 1000)
        }

        checksum = hmac.new(CHECKSUM_SECRET_KEY, 
                          f"{json_body['partyId']},{json_body['brandId']},{json_body['bonusPlanID']},{json_body['amount']},{json_body['reason']},{json_body['timestamp']}".encode(), 
                          hashlib.sha512)
        
        headers = {
            'Checksum-Fields': 'partyId,brandId,bonusPlanID,amount,reason,timestamp',
            'Checksum': base64.b64encode(checksum.digest()).decode('utf-8')
        }

        response = requests.post("https://ps-secundus.gmntc.com/ips/bonus/trigger", 
                               json=json_body, 
                               headers=headers)

        if response.status_code == 200:
            return jsonify({
                "message": f"Congratulations! You won {amount}TL Bonus Award",
                "redirect_url": "https://www.bhspwa41.com/tr/"
            })
        
        return jsonify({
            "message": "Error processing bonus",
            "redirect_url": "https://www.bhspwa41.com/tr/"
        })

    except Exception as e:
        conn.rollback()
        return jsonify({
            "message": "Error occurred",
            "redirect_url": "https://www.bhspwa41.com/tr/"
        })

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

# Add new route for the wheel game
@app.route('/wheel', methods=['GET'])
def wheel_game():
    encrypted_data = request.args.get("data")
    
    if not encrypted_data:
        return generate_html_response("Invalid request.", "https://www.bhspwa41.com/tr/")

    try:
        decrypted_data = decrypt_data(encrypted_data, SECRET_KEY)
        party_id = decrypted_data["userId"]
        
        # Check if user already played
        if is_party_id_used(party_id):
            return generate_html_response("Bonus daha önce kullanılmış.", "https://www.bhspwa41.com/tr/")
        
        # Generate a unique token for this session
        session['game_token'] = secrets.token_hex(32)
        session['party_id'] = party_id
        session['amount'] = decrypted_data["amount"]
        session['can_play'] = True
        
        # Pass the token to the template
        return render_template('wheel.html', token=session['game_token'])
        
    except Exception as e:
        return generate_html_response("Hata Oluştu", "https://www.bhspwa41.com/tr/")

@app.route('/verify_play', methods=['POST'])
def verify_play():
    if not session.get('can_play'):
        return jsonify({'valid': False, 'message': 'Session expired'})
        
    party_id = session.get('party_id')
    if not party_id:
        return jsonify({'valid': False, 'message': 'Invalid session'})
        
    # Double-check database
    if is_party_id_used(party_id):
        return jsonify({'valid': False, 'message': 'Already played'})
        
    return jsonify({'valid': True})

@app.route('/process_win', methods=['POST'])
def process_win():
    # Verify game token
    if not session.get('can_play') or request.json.get('token') != session.get('game_token'):
        return jsonify({
            "message": "Invalid session",
            "redirect_url": "https://www.bhspwa41.com/tr/"
        })

    party_id = session.get('party_id')
    if not party_id:
        return jsonify({
            "message": "Session expired",
            "redirect_url": "https://www.bhspwa41.com/tr/"
        })

    try:
        # Final database check before processing
        if is_party_id_used(party_id):
            return jsonify({
                "message": "Already played",
                "redirect_url": "https://www.bhspwa41.com/tr/"
            })

        # Validate the bonus plan ID
        bonus_plan_id = request.json.get('planId')
        if bonus_plan_id not in [2222, 4444]:
            return jsonify({
                "message": "Invalid bonus plan",
                "redirect_url": "https://www.bhspwa41.com/tr/"
            })

        # Store the party_id immediately to prevent duplicate plays
        store_party_id(party_id)
        
        # Disable further plays in this session
        session['can_play'] = False

        # Prepare the API request
        json_body = {
            "partyId": party_id,
            "brandId": 23,
            "bonusPlanID": int(bonus_plan_id),
            "amount": request.json.get('amount'),
            "reason": "test1",
            "timestamp": int(time.time() * 1000)
        }

        checksum = hmac.new(CHECKSUM_SECRET_KEY, 
                          f"{json_body['partyId']},{json_body['brandId']},{json_body['bonusPlanID']},{json_body['amount']},{json_body['reason']},{json_body['timestamp']}".encode(), 
                          hashlib.sha512)
        
        headers = {
            'Checksum-Fields': 'partyId,brandId,bonusPlanID,amount,reason,timestamp',
            'Checksum': base64.b64encode(checksum.digest()).decode('utf-8')
        }

        response = requests.post("https://ps-secundus.gmntc.com/ips/bonus/trigger", 
                               json=json_body, 
                               headers=headers)

        if response.status_code == 200:
            return jsonify({
                "message": f"Congratulations! You won {request.json.get('amount')}TL Bonus Award",
                "redirect_url": "https://www.bhspwa41.com/tr/"
            })
        
        return jsonify({
            "message": "Error processing bonus",
            "redirect_url": "https://www.bhspwa41.com/tr/"
        })

    except Exception as e:
        conn.rollback()
        return jsonify({
            "message": "Error occurred",
            "redirect_url": "https://www.bhspwa41.com/tr/"
        })

@app.route('/spin', methods=['POST'])
def spin():
    try:
        # Debug logging
        print("Spin request received")
        print(f"Session can_play: {session.get('can_play')}")
        print(f"Request token: {request.json.get('token')}")
        print(f"Session token: {session.get('game_token')}")
        
        # Check token and session
        if not session.get('can_play'):
            print("Session cannot play")
            return jsonify({
                "success": False,
                "message": "Session expired",
                "redirect_url": "https://www.bhspwa41.com/tr/"
            })
            
        # Verify token from request matches session token
        if request.json.get('token') != session.get('game_token'):
            print("Token mismatch")
            return jsonify({
                "success": False,
                "message": "Invalid token",
                "redirect_url": "https://www.bhspwa41.com/tr/"
            })

        party_id = session.get('party_id')
        if not party_id:
            print("No party_id in session")
            return jsonify({
                "success": False,
                "message": "Invalid session",
                "redirect_url": "https://www.bhspwa41.com/tr/"
            })
            
        # Check if already played
        if is_party_id_used(party_id):
            print(f"Party ID {party_id} already used")
            return jsonify({
                "success": False,
                "message": "Already played",
                "redirect_url": "https://www.bhspwa41.com/tr/"
            })

        # FIXED APPROACH: Use a fixed mapping between wheel position and reward
        # This ensures the visual result always matches the reward
        
        # Define the rewards with fixed wheel positions
        rewards = [
            {'index': 0, 'type': 'lose', 'text': 'Ödül Kazanamadınız', 'color': 'Red', 'wheel_position': 0},
            {'index': 1, 'type': 'win', 'text': '100TL Ödül Kazandınız', 'amount': 100, 'planId': 14747, 'color': 'Light Green', 'wheel_position': 1},
            {'index': 2, 'type': 'win', 'text': '150TL Ödül Kazandınız', 'amount': 150, 'planId': 14747, 'color': 'Medium Green', 'wheel_position': 2},
            {'index': 3, 'type': 'win', 'text': '250TL Ödül Kazandınız', 'amount': 250, 'planId': 14747, 'color': 'Dark Green', 'wheel_position': 3}
        ]
        
        # Randomly select a reward
        selected_reward_index = random.randint(0, 3)
        selected_reward = rewards[selected_reward_index]
        
        print(f"Selected reward: {selected_reward['text']}")
        
        # Instead of calculating a rotation angle, we'll send the wheel position directly
        # The frontend will handle positioning the wheel correctly
        wheel_position = selected_reward['wheel_position']
        
        # Process the selected reward
        if selected_reward['type'] == 'win':
            print(f"WIN result: {selected_reward['amount']}TL")
            game_id = store_game_result(
                party_id=party_id,
                result_type='win',
                amount=selected_reward['amount'],
                bonus_plan_id=selected_reward['planId']
            )
            
            # Process bonus API call
            api_success = True
            api_message = selected_reward['text']
            
            try:
                json_body = {
                    "partyId": party_id,
                    "brandId": 23,
                    "bonusPlanID": selected_reward['planId'],
                    "amount": selected_reward['amount'],
                    "reason": "test1",
                    "timestamp": int(time.time() * 1000)
                }

                checksum = hmac.new(
                    CHECKSUM_SECRET_KEY,
                    f"{json_body['partyId']},{json_body['brandId']},{json_body['bonusPlanID']},{json_body['amount']},{json_body['reason']},{json_body['timestamp']}".encode(),
                    hashlib.sha512
                )
                
                headers = {
                    'Checksum-Fields': 'partyId,brandId,bonusPlanID,amount,reason,timestamp',
                    'Checksum': base64.b64encode(checksum.digest()).decode('utf-8')
                }

                print(f"Sending API request: {json_body}")
                print(f"Headers: {headers}")
                
                response = requests.post(
                    "https://ps-secundus.gmntc.com/ips/bonus/trigger",
                    json=json_body,
                    headers=headers
                )

                print(f"API response status: {response.status_code}")
                print(f"API response body: {response.text}")

                if response.status_code != 200:
                    print(f"Bonus API failed with status {response.status_code}: {response.text}")
                    api_success = False
                    api_message = "Bonus API request failed. Please contact support."
            except Exception as api_error:
                print(f"API call error: {str(api_error)}")
                api_success = False
                api_message = "Error processing bonus. Please contact support."
        else:
            print("LOSE result")
            game_id = store_game_result(
                party_id=party_id,
                result_type='lose',
                amount=None,
                bonus_plan_id=None
            )
            api_success = True
            api_message = selected_reward['text']

        # Mark as played with the game_id
        store_party_id(party_id, game_id)
        session['can_play'] = False

        # Return success response with the wheel position
        print(f"Returning success response with message: {api_message}")
        return jsonify({
            "success": True,
            "wheel_position": wheel_position,  # Send the wheel position instead of rotation
            "message": api_message,
            "reward_index": selected_reward_index,
            "reward_text": selected_reward['text'],
            "api_success": api_success,
            "redirect_url": "https://www.bhspwa41.com/tr/"
        })

    except Exception as e:
        print(f"Error in spin: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "message": "Error occurred",
            "redirect_url": "https://www.bhspwa41.com/tr/"
        })

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
