## https://markupsafe.palletsprojects.com/en/stable/
from markupsafe import escape
from flask import Flask, request

app = Flask(__name__)


def say_hi(name):
    return f"<h1>Hi {name}!</h1>"


@app.get("/insecure")
def vulnerable_xss():
    name = request.args.get("name", "user")
    return say_hi(name)


@app.get("/secure")
def sanitized_xss():
    name = request.args.get("name", "user")
    name = escape(name)
    return say_hi(name)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
