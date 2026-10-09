import sqlite3

from flask import Flask, request

app = Flask(__name__)


def db():
    return sqlite3.connect("acme.db")


@app.route("/user")
def user():
    name = request.args.get("name", "")
    rows = db().execute("SELECT id, name FROM users WHERE name = '" + name + "'").fetchall()
    return {"users": [{"id": r[0], "name": r[1]} for r in rows]}
