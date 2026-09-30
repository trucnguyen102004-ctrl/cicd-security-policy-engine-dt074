"""Demo user service protected by the security gate (clean reference code)."""
import os
import sqlite3

from flask import Flask, jsonify, request, abort
from markupsafe import escape
from werkzeug.utils import secure_filename

app = Flask(__name__)
DB_PATH = os.environ.get("APP_DB", "app.db")
UPLOAD_ROOT = os.environ.get("UPLOAD_ROOT", "/srv/uploads")


def _db():
    return sqlite3.connect(DB_PATH)


@app.route("/users")
def find_user():
    name = request.args.get("name", "")
    with _db() as conn:
        rows = conn.execute("select id, name from users where name = ?", (name,)).fetchall()
    return jsonify(rows)


@app.route("/hello")
def hello():
    return f"<p>Hello, {escape(request.args.get('name', 'guest'))}</p>"


@app.route("/files/<name>")
def read_file(name):
    safe = secure_filename(name)
    if not safe:
        abort(400)
    with open(os.path.join(UPLOAD_ROOT, safe), encoding="utf-8") as fh:
        return fh.read()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8080")))
