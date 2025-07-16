import os
from flask import Flask, request
from urllib.parse import unquote
import re

app = Flask(__name__)


def open_file_command(file):
    return "cat {}".format(file)

def is_safe_path(path):
    return re.fullmatch(r"^[a-zA-Z0-9_.-]+$", path)

@app.get("/insecure")
def insecure_handler():
    raw_file = request.args.get("file") or "example.txt"
    
    decoded_file = unquote(unquote(raw_file))
    
    result = os.popen(open_file_command(decoded_file)).read()
    return result

@app.get("/secure")
def secure_handler():
    raw_file = request.args.get("file") or "example.txt"

    if not is_safe_path(raw_file):
        return "Invalid file path", 400
    
    decoded_file = unquote(unquote(raw_file))

    result = os.popen(open_file_command(decoded_file)).read()
    return result

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
