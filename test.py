from jwt_lite import create_jwt, decode_jwt, get_claims
import time
token = create_jwt({"sub":"user1","role":"admin"}, "mysecret", exp_seconds=3600)
assert token.count(".") == 2
h, p = decode_jwt(token, "mysecret")
assert h["alg"] == "HS256"
assert p["sub"] == "user1"
assert p["role"] == "admin"
assert "exp" in p and "iat" in p
try: decode_jwt(token, "wrongsecret"); assert False
except ValueError: pass
claims = get_claims(token)
assert claims["sub"] == "user1"
# Expired token
expired = create_jwt({"sub":"x"}, "s", exp_seconds=-1)
try: decode_jwt(expired, "s"); assert False
except ValueError: pass
print("jwt_lite tests passed")
