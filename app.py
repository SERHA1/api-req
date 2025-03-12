@app.route('/webhook', methods=['GET'])
def webhook():
    encrypted_data = request.args.get("data")

    if not encrypted_data:
        return generate_html_response("Hata Oluştu", "https://www.bhspwa41.com/tr/")

    try:
        decrypted_data = decrypt_data(encrypted_data, SECRET_KEY)
    except Exception as e:
        return generate_html_response("Hata Oluştu", "https://www.bhspwa41.com/tr/")

    party_id = decrypted_data["userId"]

    try:
        if is_party_id_used(party_id):
            return generate_html_response("Bonus daha önce kullanılmış.", "https://www.bhspwa41.com/tr/")

        store_party_id(party_id)

        json_body = {
            "partyId": party_id,
            "brandId": 23,
            "bonusPlanID": 14747,
            "amount": decrypted_data["amount"],
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

        response = requests.post("https://ps-secundus.gmntc.com/ips/bonus/trigger", json=json_body, headers=headers)

        return jsonify({"status": "success", "message": "Request sent to API", "api_response": response.json()})

    except Exception as e:
        conn.rollback()
        return generate_html_response("Hata Oluştu", "https://www.bhspwa41.com/tr/")


def generate_html_response(message, redirect_url):
    return f"""
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Bilgilendirme</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                text-align: center;
                margin: 50px;
            }}
            .counter {{
                font-size: 24px;
                margin-top: 20px;
                font-weight: bold;
            }}
            .circle {{
                width: 50px;
                height: 50px;
                line-height: 50px;
                border-radius: 50%;
                background: red;
                color: white;
                display: inline-block;
                font-size: 20px;
                font-weight: bold;
            }}
        </style>
        <script>
            let countdown = 5;
            function updateCounter() {{
                document.getElementById("counter").innerText = countdown;
                if (countdown === 0) {{
                    window.location.href = "{redirect_url}";
                }} else {{
                    countdown--;
                    setTimeout(updateCounter, 1000);
                }}
            }}
            window.onload = updateCounter;
        </script>
    </head>
    <body>
        <h1>{message}</h1>
        <div class="counter">Yönlendiriliyor... <span class="circle" id="counter">5</span></div>
    </body>
    </html>
    """
