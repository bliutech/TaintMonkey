from flask import Flask, request
from html_sanitizer import Sanitizer
from flask import render_template

app = Flask(__name__)


def home(name):
    return render_template("home.html", name=name)


@app.get("/insecure")
def insecure_xss():
    name = request.args.get("name", "user")
    return home(name)


@app.get("/secure")
def secure_xss():
    name = request.args.get("name", "user")
    name = Sanitizer().sanitize(name)
    return home(name)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
