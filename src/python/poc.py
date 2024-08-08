from saml2 import config
from saml2 import client
from saml2.response import AuthnResponse
import base64
import xml.etree.ElementTree as ET

def validate_saml_response(saml_response_xml, idp_metadata_url):
    # Create a SAML configuration
    saml_config = config.SPConfig()

    # Load configuration from file or directly from a dictionary
    saml_config.load({
        'entityid': 'qwerty',  # Replace with your SP entity ID
        'metadata': {
            'remote': [
                {
                    'url': idp_metadata_url,  # URL to IdP metadata
                }
            ]
        },
        'cert_file': 'certificates/certificate.pem',
       
    })

    print(saml_config.load)

    # Initialize the client with the configuration
    saml_client = client.Saml2Client(config=saml_config)

    # Parse the SAML response
    try:
        # Decode and parse the SAML response
        saml_response = base64.b64decode(saml_response_xml)
        tree = ET.ElementTree(ET.fromstring(saml_response))
        root = tree.getroot()

        # Check if the root tag is 'Response' which indicates a SAML response
        if root.tag.endswith('Response'):
            print("SAML Response is valid!")
        else:
            print("Invalid SAML Response")
    except Exception as e:
        print(f"Validation failed: {e}")

if __name__ == "__main__":
    saml_response_file = 'saml_assertions/saml_response.xml'
    idp_metadata_url = 'https://auth.pingone.com/7d9adc6d-55a8-48fb-8528-7404c5f80af7/saml20/metadata/5312a580-98a9-461e-899b-d4c07c142e7b'

    # Load SAML response XML
    with open(saml_response_file, 'r') as file:
        saml_response_xml = file.read()

    # Validate the SAML response
    validate_saml_response(saml_response_xml, idp_metadata_url)
