"""SARD-derived test case (Juliet template ported to Python).
CWE: CWE-89
Label: bad
Template: sources-sinks-01 (bad / goodG2B / goodB2G), flow variant 01
"""
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/bad")
def bad():
    # POTENTIAL FLAW: read data from the query string
    data = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # POTENTIAL FLAW: data concatenated into SQL statement
    cur.execute("select * from users where name='" + data + "'")
    return str(cur.fetchall())
