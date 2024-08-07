from flask import Flask, request, jsonify, redirect
import os
import base64
import urllib.parse
from dotenv import load_dotenv


app = Flask(__name__)

# Configuration settings
SAML_SAVE_DIR = "saml_assertions"

# Ensure the directory exists
os.makedirs(SAML_SAVE_DIR, exist_ok=True)

def decode_base64(encoded_str):
    """Decode a base64 encoded string."""
    try:
        return base64.b64decode(encoded_str).decode('utf-8')
    except (TypeError, base64.binascii.Error) as e:
        raise ValueError("Invalid base64 encoding") from e

def save_to_file(filename, content):
    """Save content to a file."""
    with open(filename, 'w') as f:
        f.write(content)

@app.route('/saml', methods=['POST'])
def saml_relay():
    """Handle SAML assertions."""
    saml_assertion = request.form.get('SAMLRequest')

    if not saml_assertion:
        return jsonify({"error": "Missing SAMLRequest"}), 400

    try:
        # Decode base64 encoded SAML assertion
        decoded_saml_assertion = decode_base64(saml_assertion)

        # Save decoded SAML request
        request_filename = os.path.join(SAML_SAVE_DIR, 'saml_request.xml')
        save_to_file(request_filename, decoded_saml_assertion)
        print("SAMLRequest successfully decoded and saved.")

        # URL-encode the base64 encoded SAML assertion
        encoded_saml_assertion = urllib.parse.quote_plus(saml_assertion)

        # Redirect to PingOne with the SAML assertion
        okta_sso_url = f'{os.getenv("OKTA_SSO_URL")}{encoded_saml_assertion}'

        return redirect(okta_sso_url)

    except ValueError as e:
        print(f"Error processing SAMLRequest: {e}")
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    load_dotenv()
    app.run(debug=True, host='0.0.0.0', port=3000)
