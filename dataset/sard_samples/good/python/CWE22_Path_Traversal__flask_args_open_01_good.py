"""SARD-derived test case (Juliet template ported to Python).
CWE: CWE-22
Label: good
Template: sources-sinks-01 (bad / goodG2B / goodB2G), flow variant 01
"""
import os
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
ROOT = "/srv/uploads"


@app.route("/goodG2B")
def good_g2b():
    # FIX: use a hardcoded string
    data = "foo.txt"
    with open(os.path.join(ROOT, data)) as fh:
        return fh.readline()


@app.route("/goodB2G")
def good_b2g():
    data = request.args.get("file")
    # FIX: strip directory components before joining
    with open(os.path.join(ROOT, secure_filename(data))) as fh:
        return fh.readline()
