"""SARD-derived test case (Juliet template ported to Python).
CWE: CWE-79
Label: bad
Template: sources-sinks-01 (bad / goodG2B / goodB2G), flow variant 01
"""
from flask import Flask, request, make_response

app = Flask(__name__)


@app.route("/bad")
def bad():
    # POTENTIAL FLAW: read data from the query string
    data = request.args.get("name")
    # POTENTIAL FLAW: display of data in web page without any encoding
    return make_response("<br>bad(): data = " + data)
