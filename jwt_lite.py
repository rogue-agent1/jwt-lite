#!/usr/bin/env python3
"""JWT creation and validation (HMAC-SHA256). Zero dependencies."""
import hmac, hashlib, json, time

def _b64url_encode(data):
    import base64
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(s):
    import base64
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def create_jwt(payload, secret, exp_seconds=3600):
    header = {"alg":"HS256","typ":"JWT"}
    if exp_seconds:
        payload = dict(payload)
        payload["iat"] = int(time.time())
        payload["exp"] = int(time.time()) + exp_seconds
    h = _b64url_encode(json.dumps(header))
    p = _b64url_encode(json.dumps(payload))
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"

def decode_jwt(token, secret=None, verify=True):
    parts = token.split(".")
    if len(parts) != 3: raise ValueError("Invalid JWT format")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    if verify and secret:
        expected = hmac.new(secret.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
        actual = _b64url_decode(parts[2])
        if not hmac.compare_digest(expected, actual):
            raise ValueError("Invalid signature")
        if "exp" in payload and payload["exp"] < time.time():
            raise ValueError("Token expired")
    return header, payload

def get_claims(token):
    _, payload = decode_jwt(token, verify=False)
    return payload

if __name__ == "__main__":
    token = create_jwt({"sub":"user123","name":"Alice"}, "secret")
    print(f"JWT: {token[:50]}...")
    h, p = decode_jwt(token, "secret")
    print(f"Claims: {p}")
