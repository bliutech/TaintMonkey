# https://www.freeformatter.com/html-escape.html

from flask import Flask, request
import html

app = Flask(__name__)


def suspicious_input(name):
    # html escape
    upd_name = html.escape(name)
    if name != upd_name:
        return True
    return False


def say_hi(name):
    return f"<h1>Hi {name}!</h1>"


@app.route("/insecure-xss")
def insecure_xss():
    name = request.args.get("name", "user")
    return say_hi(name)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
