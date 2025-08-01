# https://lxml.de/api/lxml.html.clean.Cleaner-class.html

from flask import Flask, request
from lxml.html.clean import Cleaner

app = Flask(__name__)


# test: curl -X POST -d "username=<script>alert('XSS')</script>"
@app.route("/insecure_welcome", methods=["POST"])
def insecure_welcome():
    if request.method == "POST":
        username = request.form.get("username", "")
        return f"Welcome, {username}!"
    return "Welcome!"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
