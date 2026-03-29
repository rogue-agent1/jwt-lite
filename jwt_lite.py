#!/usr/bin/env python3
"""JWT encoder/decoder with HMAC-SHA256 signing."""
import sys, json, base64, hmac, hashlib, time

def b64url_encode(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s):
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def encode(payload, secret, algorithm="HS256"):
    header = {"alg": algorithm, "typ": "JWT"}
    segments = [b64url_encode(json.dumps(header)), b64url_encode(json.dumps(payload))]
    signing_input = ".".join(segments)
    if algorithm == "HS256":
        sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    else:
        raise ValueError(f"Unsupported: {algorithm}")
    segments.append(b64url_encode(sig))
    return ".".join(segments)

def decode(token, secret, verify=True):
    parts = token.split(".")
    if len(parts) != 3: raise ValueError("Invalid JWT")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    if verify:
        signing_input = f"{parts[0]}.{parts[1]}"
        expected = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
        actual = b64url_decode(parts[2])
        if not hmac.compare_digest(expected, actual):
            raise ValueError("Invalid signature")
        if "exp" in payload and payload["exp"] < time.time():
            raise ValueError("Token expired")
    return payload

def test():
    secret = "my-secret-key"
    payload = {"sub": "1234", "name": "Rogue", "iat": 1700000000}
    token = encode(payload, secret)
    assert token.count(".") == 2
    decoded = decode(token, secret)
    assert decoded["sub"] == "1234"
    assert decoded["name"] == "Rogue"
    # Invalid signature
    try:
        decode(token, "wrong-key")
        assert False, "Should have raised"
    except ValueError: pass
    # Decode without verify
    decoded2 = decode(token, "", verify=False)
    assert decoded2["name"] == "Rogue"
    print("  jwt_lite: ALL TESTS PASSED")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test": test()
    else: print("JWT encoder/decoder")
