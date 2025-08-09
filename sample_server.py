import os

import requests
from flask import Flask, request, jsonify
from flask_oidc import OpenIDConnect

app = Flask(__name__)

# URL del provider OIDC (sostituire con il tuo URL reale)
OIDC_SERVER_URL = 'http://127.0.0.1:8080'

# Ottieni i dettagli di configurazione dal provider OIDC
oidc_config = requests.get(f'{OIDC_SERVER_URL}/.well-known/openid-configuration').json()

# Configurazione per OIDC
app.config.update({
    'SECRET_KEY': 'random_secret_key',
    'OIDC_CLIENT_SECRETS': {
        'web': {
            'client_id': 'your_client_id',
            'client_secret': 'your_client_secret',
            'auth_uri': oidc_config['authorization_endpoint'],
            'token_uri': oidc_config['token_endpoint'],
            'userinfo_uri': oidc_config['userinfo_endpoint'],
            'issuer': oidc_config['issuer'],
        }
    },
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': 'your_realm',
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post',
})

oidc = OpenIDConnect(app)

@app.route('/auth', methods=['POST'])
def authenticate():
    """Autentica l'utente e restituisce un token di accesso."""
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    # Simula chiamata al server OIDC per ottenere il token
    token_response = oidc.token_from_credentials({
        'username': username,
        'password': password,
        'grant_type': 'password',
        'client_id': app.config['OIDC_CLIENT_ID'],
        'client_secret': app.config['OIDC_CLIENT_SECRET'],
        'token_url': app.config['OIDC_TOKEN_ENDPOINT']
    })

    if 'access_token' in token_response:
        return jsonify({"access_token": token_response['access_token']}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401


@app.route('/verify', methods=['GET'])
def verify_token():
    """Verifica il token Bearer fornito nell'intestazione Authorization."""
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Authorization header required"}), 400

    access_token = auth_header.split(" ")[1]

    # Verifica il token tramite introspezione
    introspect_url = app.config['OIDC_INTROSPECTION_ENDPOINT']
    introspection_response = oidc.introspect_token(access_token, introspect_url)

    if introspection_response['active']:
        return jsonify({"message": "Token is valid", "user_info": introspection_response}), 200
    else:
        return jsonify({"error": "Invalid token"}), 401


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8081)))
