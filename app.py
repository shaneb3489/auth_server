import os
import json
import uuid
import requests
from urllib.parse import urlencode
from flask import Flask, request, redirect, session, jsonify, abort

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "replace-me")

# Configuration
# Replace these with your Okta domain and app credentials.
OKTA_ISSUER = "https://your-okta-domain.okta.com/oauth2/default"
OKTA_AUTHORIZATION_ENDPOINT = f"{OKTA_ISSUER}/v1/authorize"
OKTA_TOKEN_ENDPOINT = f"{OKTA_ISSUER}/v1/token"
OKTA_CLIENT_ID = "your_okta_client_id"
OKTA_CLIENT_SECRET = "your_okta_client_secret"

# This server’s own configuration
# In a real deployment, these would be served over HTTPS.
OUR_ISSUER = "http://localhost:5000"
OUR_CLIENTS = {
    "our_client_id": {
        "client_secret": "our_client_secret",
        "redirect_uris": ["http://localhost:5000/client_callback"],
        "allowed_scopes": ["openid", "profile"],
    }
}

# Simple in-memory store for state and user sessions
# In production, use a database or a proper session store.
STATE_STORE = {}

@app.route("/authorize")
def authorize():
    # Parse client request
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    response_type = request.args.get("response_type")
    scope = request.args.get("scope", "")

    # Validate client and redirect URI
    client = OUR_CLIENTS.get(client_id)
    if not client or redirect_uri not in client["redirect_uris"]:
        return abort(400, "Invalid client or redirect_uri")

    if response_type != "code":
        return abort(400, "Unsupported response_type")

    # Generate state to prevent CSRF attacks
    state = str(uuid.uuid4())
    STATE_STORE[state] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope
    }

    # Construct the Okta authorization URL
    # PKCE or nonce might be needed for certain security flows, omitted here for brevity.
    okta_params = {
        "client_id": OKTA_CLIENT_ID,
        "redirect_uri": f"{OUR_ISSUER}/callback",
        "response_type": "code",
        "scope": scope,
        "state": state
    }
    auth_url = f"{OKTA_AUTHORIZATION_ENDPOINT}?{urlencode(okta_params)}"
    return redirect(auth_url)


@app.route("/callback")
def callback():
    # This endpoint receives the callback from Okta with a code and state
    code = request.args.get("code")
    state = request.args.get("state")

    # Validate state
    stored_state = STATE_STORE.pop(state, None)
    if not stored_state:
        return abort(400, "Invalid or expired state")

    # Exchange code for tokens at Okta token endpoint
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": f"{OUR_ISSUER}/callback"
    }
    auth = (OKTA_CLIENT_ID, OKTA_CLIENT_SECRET)
    headers = {"Accept": "application/json"}
    token_response = requests.post(OKTA_TOKEN_ENDPOINT, data=data, auth=auth, headers=headers)

    if token_response.status_code != 200:
        return abort(400, "Failed to exchange code at Okta")

    tokens = token_response.json()

    # In a more complex scenario, you might introspect or transform these tokens, 
    # or issue your own signed tokens. For now, we just store them and associate 
    # them with the user session if needed.

    # Redirect user back to the client's redirect URI with an authorization code in 
    # a typical auth code flow scenario. However, since we are fronting Okta, we 
    # might stop here and let the /token endpoint in this server handle issuing tokens 
    # from these credentials.

    # For demonstration, let's store the tokens in a "session" keyed by state:
    # In a real scenario, you would have a database or a more permanent store.
    session["okta_tokens"] = tokens
    client_id = stored_state["client_id"]
    redirect_uri = stored_state["redirect_uri"]

    # Redirect back to client app with a code representing these tokens stored on the server
    # We'll generate a temporary code to represent this authorization.
    # The client will then use this code at our /token endpoint to get the final tokens.
    auth_code = str(uuid.uuid4())
    session[auth_code] = {
        "tokens": tokens,
        "client_id": client_id
    }

    return redirect(f"{redirect_uri}?code={auth_code}&state={state}")


@app.route("/token", methods=["POST"])
def token():
    # The client exchanges the code for tokens on our server
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")

    # Validate client
    client = OUR_CLIENTS.get(client_id)
    if not client or client["client_secret"] != client_secret:
        return abort(401, "Invalid client credentials")

    if grant_type != "authorization_code":
        return abort(400, "Unsupported grant_type")

    # Find the tokens associated with this code
    auth_data = session.pop(code, None)
    if not auth_data or auth_data["client_id"] != client_id:
        return abort(400, "Invalid code")

    tokens = auth_data["tokens"]

    # Here you could:
    # - Return the Okta tokens directly
    # - Or issue your own access_token and refresh_token signed by your server
    # For simplicity, let's just return what we got from Okta.
    # (In a real scenario, ensure scopes and claims are what you want to pass through.)

    return jsonify({
        "access_token": tokens["access_token"],
        "token_type": tokens.get("token_type", "Bearer"),
        "expires_in": tokens.get("expires_in", 3600),
        "refresh_token": tokens.get("refresh_token"),
        "id_token": tokens.get("id_token"),
        "scope": tokens.get("scope")
    })


@app.route("/.well-known/oauth-authorization-server")
def metadata():
    base_url = OUR_ISSUER
    return jsonify({
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "jwks_uri": f"{base_url}/.well-known/jwks.json",  # if you implement JWKS
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "scopes_supported": ["openid", "profile"]
    })

if __name__ == "__main__":
    # In production, run with a production WSGI server and HTTPS termination.
    app.run(host="0.0.0.0", port=5000, debug=True)
