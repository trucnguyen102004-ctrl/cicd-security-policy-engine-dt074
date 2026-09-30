"""SARD-derived test case (Juliet template ported to Python).
CWE: CWE-89
Label: good
Template: sources-sinks-01 (bad / goodG2B / goodB2G), flow variant 01
"""
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/goodG2B")
def good_g2b():
    # FIX: use a hardcoded string
    data = "foo"
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("select * from users where name='" + data + "'")
    return str(cur.fetchall())


@app.route("/goodB2G")
def good_b2g():
    data = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # FIX: parameterised query
    cur.execute("select * from users where name=?", (data,))
    return str(cur.fetchall())
