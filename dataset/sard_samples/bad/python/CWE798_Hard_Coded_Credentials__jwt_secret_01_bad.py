"""SARD-derived test case (Juliet template ported to Python).
CWE: CWE-798
Label: bad
Template: sources-sinks-01 (bad / goodG2B / goodB2G), flow variant 01
"""
import datetime
import jwt

# FLAW: signing secret hard-coded in source
api_secret_key = "Zq8vN3kLx7Tb2RmW9pYc4HsJ6dFa1GeU"


def bad(user_id: str) -> str:
    payload = {"sub": user_id,
               "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
    return jwt.encode(payload, api_secret_key, algorithm="HS256")
