#https://www.freeformatter.com/html-escape.html

from flask import Flask, request
import html

app = Flask(__name__)

def say_hi(name):
    return f"<h1>Hi {name}!</h1>"

@app.route("/xss")
def vulnerable_xss():
    name = request.args.get("name", "user")
    return say_hi(name)

@app.route("/xss_sanitized")
def sanitized_xss():
    name = request.args.get("name", "user")
    # html escape
    name = html.escape(name)
    return say_hi(name)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

