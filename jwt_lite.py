#!/usr/bin/env python3
"""jwt_lite: Minimal JWT (HS256) implementation."""
import hashlib, hmac, json, base64, time, sys

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)

def encode(payload: dict, secret: str, exp: int = 0) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    if exp > 0:
        payload = {**payload, "exp": int(time.time()) + exp}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig_input = f"{h}.{p}"
    sig = hmac.new(secret.encode(), sig_input.encode(), hashlib.sha256).digest()
    return f"{sig_input}.{b64url_encode(sig)}"

def decode(token: str, secret: str, verify: bool = True) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid token format")
    h, p, s = parts
    if verify:
        sig_input = f"{h}.{p}"
        expected = hmac.new(secret.encode(), sig_input.encode(), hashlib.sha256).digest()
        actual = b64url_decode(s)
        if not hmac.compare_digest(expected, actual):
            raise ValueError("Invalid signature")
    payload = json.loads(b64url_decode(p))
    if verify and "exp" in payload and payload["exp"] < time.time():
        raise ValueError("Token expired")
    return payload

def test():
    secret = "my-secret"
    payload = {"sub": "1234", "name": "Test"}
    token = encode(payload, secret)
    assert token.count(".") == 2
    decoded = decode(token, secret)
    assert decoded["sub"] == "1234"
    assert decoded["name"] == "Test"
    # Bad secret
    try:
        decode(token, "wrong")
        assert False
    except ValueError:
        pass
    # Expired
    token2 = encode({"sub": "1"}, secret, exp=-10)
    # Manually craft expired token
    h, p, s = token2.split(".")
    pay = json.loads(b64url_decode(p))
    pay["exp"] = int(time.time()) - 100
    p2 = b64url_encode(json.dumps(pay, separators=(",", ":")).encode())
    sig_input = f"{h}.{p2}"
    sig = hmac.new(secret.encode(), sig_input.encode(), hashlib.sha256).digest()
    expired_token = f"{sig_input}.{b64url_encode(sig)}"
    try:
        decode(expired_token, secret)
        assert False
    except ValueError as e:
        assert "expired" in str(e).lower()
    # No verify
    decoded_nv = decode(token, "wrong", verify=False)
    assert decoded_nv["sub"] == "1234"
    print("All tests passed!")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test()
    else:
        print("Usage: jwt_lite.py test")
