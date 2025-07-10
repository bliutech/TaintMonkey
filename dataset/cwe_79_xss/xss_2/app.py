from flask import Flask, request
import html

app = Flask(__name__)

def sayHi(name):
    return f"<h1>Hi {name}!</h1>"

@app.route("/xss")
def vulnerable_xss():
    name = request.args.get("name", "")
    return sayHi(name)

@app.route("/xss_sanitized")
def sanitized_xss():
    name = request.args.get("name", "")
    # html
    name = html.escape(name)
    return sayHi(name)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

