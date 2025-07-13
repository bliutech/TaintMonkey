from flask import Flask, request, make_response
from html import escape

app = Flask(__name__)


@app.route("/set_cookie")
def set_cookie():
    resp = make_response("cookie set")
    resp.set_cookie("username", "Aarav")
    return resp


# <script>alert(document.cookie)</script>
# xss attack ^
@app.route("/insecure_cookie")
def insecure_cookie():
    username = request.args.get("username", "")
    return f"How are you, {username}?"


@app.route("/secure_cookie")
def secure_cookie():
    username = request.args.get("username", "")
    username = escape(username)
    return f"How are you, {username}?"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
