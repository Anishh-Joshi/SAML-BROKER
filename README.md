# Flask SAML Relay Application

## Overview

This Flask application handles SAML assertions sent via a POST request, decodes the base64 encoded SAML assertion, saves it to a file, and then redirects to a configured URL with the SAML assertion. This application is intended to be used in scenarios where SAML requests need to be processed and forwarded to an Identity Provider (IdP) like Okta or PingOne.

## Features

- Decodes base64 encoded SAML assertions.
- Saves the decoded SAML request to a file.
- Redirects to a configured URL with the SAML assertion.
- Handles errors related to invalid base64 encoding.

## Setup

### Prerequisites

- Python 3.6 or higher
- Flask

### Installation

1. **Clone the Repository**

    ```bash
    git clone https://github.com/Anishh-Joshi/SAML-BROKER
    cd SAML-BROKER
    ```

2. **Create a Virtual Environment**

    ```bash
    python -m venv venv
    ```

3. **Activate the Virtual Environment**

    - On Windows:

        ```bash
        venv\Scripts\activate
        ```

    - On macOS/Linux:

        ```bash
        source venv/bin/activate
        ```

4. **Install Dependencies**

    ```bash
    pip install -r src/python/requirements.txt
    ```

5. **Set Up Environment Variables**

    Create a `.env` file in the root directory of the project and add the following environment variables:

    ```env
    OKTA_SSO_URL=https://your-okta-sso-url
    ```

6. **Run the Application**

    ```bash
    python src/python/app.py
    ```

    The application will start and listen on port 3000.

## Endpoints

### `POST /saml`

Handles SAML assertions sent via POST request.

**Parameters:**

- `SAMLRequest` (required): Base64 encoded SAML assertion.

**Response:**

- On success: Redirects to the configured URL with the SAML assertion.
- On failure: Returns a JSON error message.

**Example Request:**

```bash
curl -X POST http://localhost:3000/saml -d 'SAMLRequest=<base64-encoded-saml-assertion>'
