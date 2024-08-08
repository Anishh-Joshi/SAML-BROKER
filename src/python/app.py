
###########################-------------------------------IDP BASED RELAY-------------------------------###########################
"""
This Flask application handles IdP-initiated SAML authentication. The Identity Provider (IdP) initiates 
the flow by sending a SAML assertion to this server. The server intercepts the SAML assertion, verifies 
and processes it, and then relays it to the SAML Mock SP. This completes the authentication relay process.
"""

###########################------------------------------- SP BASED RELAY-------------------------------###########################

"""
This Flask application handles SP-initiated SAML authentication. The Service Provider (SP) in this case is 
a SAML Mock SP. The SAML request is intercepted by this server, which decodes and verifies the SAML request 
and then relays it to the Okta Identity Provider (IdP) for authentication. Upon successful authentication, 
Okta redirects back to the SAML Mock SP with a SAML assertion, completing the authentication relay process.
"""


from flask import Flask, request, jsonify, redirect
import os
import base64
import urllib.parse
from dotenv import load_dotenv

import xml.etree.ElementTree as ET

app = Flask(__name__)

# Configuration settings
SAML_SAVE_DIR = "saml_assertions"

IDP_FLAG = True

# Ensure the directory exists
os.makedirs(SAML_SAVE_DIR, exist_ok=True)



def extract_certificate(saml_response):
    # Parse the SAML response
    root = ET.fromstring(saml_response)

    # Find the X509Certificate element
    namespace = {'ds': 'http://www.w3.org/2000/09/xmldsig#'}
    cert_element = root.find('.//ds:X509Certificate', namespace)
    
    if cert_element is not None:
        # Extract and clean the certificate
        cert_data = cert_element.text.strip()
        return cert_data
    else:
        raise ValueError("X509Certificate element not found in the SAML response.")

def save_certificate_to_pem(cert_data, filename):
    file_path = os.path.join('certificates', filename)
    # Convert to PEM format and save to file
    pem_data = f"-----BEGIN CERTIFICATE-----\n"
    pem_data += '\n'.join(cert_data[i:i+64] for i in range(0, len(cert_data), 64))
    pem_data += "\n-----END CERTIFICATE-----\n"

    with open(file_path, 'w') as file:
        file.write(pem_data)

def hendle_cert(saml_response, output_file):
    cert_data = extract_certificate(saml_response)
    save_certificate_to_pem(cert_data, output_file)
    print(f"Certificate saved to {output_file}")

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
    saml_request = request.form.get('SAMLResponse' if IDP_FLAG else 'SAMLRequest')

    if not saml_request:
        return jsonify({"error": "Missing " + 'SAMLResponse' if IDP_FLAG else 'SAMLRequest'}), 400

    try:
        # Decode base64 encoded SAML assertion
        decoded_saml_assertion = decode_base64(saml_request)
        hendle_cert(saml_response=decoded_saml_assertion,output_file="certificate.pem")

        # Save decoded SAML data
        file_suffix = 'response' if IDP_FLAG else 'request'
        file_name = f'saml_{file_suffix}.xml'
        file_path = os.path.join(SAML_SAVE_DIR, file_name)
        save_to_file(file_path, decoded_saml_assertion)

        # URL-encode the base64 encoded SAML assertion
        encoded_saml_assertion = urllib.parse.quote_plus(saml_request)

        if IDP_FLAG:
            # Redirect to SAML MOCK with the SAML assertion
            redirect_url = f'{os.getenv("ACS_URL_DESTINATION")}{encoded_saml_assertion}'
        else:
            # Redirect to OKTA with the SAML Request
            redirect_url = f'{os.getenv("OKTA_SSO_UR_SP_INITIATED")}{encoded_saml_assertion}'
        return redirect(redirect_url)


    except ValueError as e:
        print(f"Error processing SAMLRequest: {e}")
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    load_dotenv()
    app.run(debug=True, host='0.0.0.0', port=3000)
