from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)

@app.route("/insecure")
def improper_neutralization():
    input = request.args.get("input")
    if not input:
        return "No valid input"
    return input

@app.route("/secure")
def proper_neutralization():
    input = request.args.get("input")
    if not input:
        return "No valid input"
    sanitized_input = neutralize(input)
    return sanitized_input

def neutralize(input):
    return escape(input)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)