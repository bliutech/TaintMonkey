# https://bleach.readthedocs.io/en/latest/clean.html
from flask import Flask, request
import bleach

app = Flask(__name__)


def welcome(name):
    return f"<h1>Welcome to GSET, {name}!</h1>"


@app.get("/insecure")
def insecure_xss():
    name = request.args.get("name", "user")
    return welcome(name)


@app.get("/secure")
def secure_xss():
    name = request.args.get("name", "user")
    upd_name = bleach.clean(name)

    if name != upd_name:
        return "Invalid input detected and cleaned", 400

    return welcome(name)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
