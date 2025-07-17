import os
from flask import Flask, request
import re

app = Flask(__name__)

def open_file_command(file):
    return "cat {}".format(file)

def is_safe_path(path):
    return re.match(r"^[a-zA-Z0-9_.-]+$", path)

@app.get("/secure")
def secure_handler():
    file = request.args.get("file") or "example.txt"

    if not is_safe_path(file):
        return "Invalid file path"

    res = os.popen(open_file_command(file)).read()
    return res

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
 