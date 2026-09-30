"""SARD-derived test case (Juliet template ported to Python).
CWE: CWE-22
Label: bad
Template: sources-sinks-01 (bad / goodG2B / goodB2G), flow variant 01
"""
import os
from flask import Flask, request

app = Flask(__name__)
ROOT = "/srv/uploads"


@app.route("/bad")
def bad():
    # POTENTIAL FLAW: read data from the query string
    data = request.args.get("file")
    # POTENTIAL FLAW: no validation of concatenated path
    with open(os.path.join(ROOT, data)) as fh:
        return fh.readline()
