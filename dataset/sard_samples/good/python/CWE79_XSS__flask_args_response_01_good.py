"""SARD-derived test case (Juliet template ported to Python).
CWE: CWE-79
Label: good
Template: sources-sinks-01 (bad / goodG2B / goodB2G), flow variant 01
"""
from flask import Flask, request, make_response
from markupsafe import escape

app = Flask(__name__)


@app.route("/goodG2B")
def good_g2b():
    # FIX: use a hardcoded string
    data = "foo"
    return make_response("<br>goodG2B(): data = " + data)


@app.route("/goodB2G")
def good_b2g():
    data = request.args.get("name")
    # FIX: HTML-encode before output
    return make_response("<br>goodB2G(): data = " + escape(data))
