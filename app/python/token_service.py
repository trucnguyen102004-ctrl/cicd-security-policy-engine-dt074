"""SARD-derived test case (Juliet template ported to Python).
CWE: CWE-798
Label: good
Template: sources-sinks-01 (bad / goodG2B / goodB2G), flow variant 01
"""
import datetime
import os
import jwt


def good(user_id: str) -> str:
    # FIX: read the signing secret from the environment / secret manager
    api_secret_key = os.environ["JWT_SIGNING_KEY"]
    payload = {"sub": user_id,
               "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
    return jwt.encode(payload, api_secret_key, algorithm="HS256")
