import base64
import hmac
import hashlib
import json

def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=')

def create_jwt(header, payload, secret):
    encoded_header = base64url_encode(json.dumps(header).encode())
    encoded_payload = base64url_encode(json.dumps(payload).encode())
    
    signature_input = b'.'.join([encoded_header, encoded_payload])
    signature = hmac.new(secret.encode(), signature_input, hashlib.sha256).digest()
    encoded_signature = base64url_encode(signature)
    
    jwt_token = b'.'.join([encoded_header, encoded_payload, encoded_signature])
    return jwt_token.decode()

header = {
    "alg": "HS256",
    "typ": "JWT"
{
  "sub": "marriott_ios",
  "cts": "OAUTH2_STATELESS_GRANT",
  "auditTrackingId": "a7fe2d99-1efa-4947-8467-4f785b0309dc-5803436",
  "subname": "sub",
  "iss": "akana",
  "tokenName": "access_token",
  "token_type": "Bearer",
  "authGrantId": "uvv84ghoqi5d": [
    "marriott_ios",
    "api.marriott.com"
  ],
  "nbf": 1720645386,
  "grant_type": "client_credentials",
  "scope": [
    "email",
   ],
  "auth_time": 1720645386,
  "realm": "/Customers",
  "exp": 1720647186,
  "iat": 1720645386,
  "expires_in": 1800,
  "jti": "LrnhYICSALM87nYZQKyUiypA0YQ",
  "client_id": "EJH_Akana",
  "azp": "marriott_ios"
}
secret = "password"

jwt_token = create_jwt(header, payload, secret)
print(jwt_token)
