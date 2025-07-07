import re
import os
from flask import Flask, request

app = Flask(__name__)


@app.get("/insecure")
def insecure_handler():
    file = request.args.get("file") or "example.txt"
    res = os.popen(f"cat {file}").read()
    return res


def is_safe_path(path):
    return re.match(r"^[a-zA-Z0-9_.-]+$", path)


@app.get("/secure")
def secure_handler():
    file = request.args.get("file") or "example.txt"

    if not is_safe_path(file):
        return "Invalid file path"

    res = os.popen(f"cat {file}").read()
    return res


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
