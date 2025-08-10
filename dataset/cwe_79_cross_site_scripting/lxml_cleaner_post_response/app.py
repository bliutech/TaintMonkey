# https://lxml.de/api/lxml.html.clean.Cleaner-class.html


from flask import Flask, request
from lxml.html.clean import Cleaner


app = Flask(__name__)


def welcome(name):
    return f"Welcome, {name}!"


# test: curl -X POST -d "username=<script>alert('XSS')</script>"
@app.route("/insecure_welcome", methods=["POST"])
def insecure_welcome():
    if request.method == "POST":
        username = request.form.get("username", "")
        return welcome(username)
    return "Welcome!"


@app.route("/secure_welcome", methods=["POST"])
def secure_welcome():
    if request.method == "POST":
        username = request.form.get("username", "")
        cleaner = Cleaner(scripts=True, javascript=True, style=True)
        cleaned_username = cleaner.clean_html(username)
        return welcome(cleaned_username)
    return "Welcome!"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
