import os
import re
import unicodedata
from flask import Flask, request

app = Flask(__name__)

def open_file_command(file):
    return "cat {}".format(file)

def is_safe_path(path):
    return re.fullmatch(r"^[a-zA-Z0-9_.-]+$", path)

def normalize_input(user_input):
    # unicode protection protects against unicode tricks that get a system to run malicious code
    return unicodedata.normalize("NFC", user_input.strip())

@app.get("/secure")
def secure_handler():
    raw_file = request.args.get("file") or "example.txt"
    normalized_file = normalize_input(raw_file)

    if not is_safe_path(normalized_file):
        return "Invalid file path", 400

    result = os.popen(open_file_command(normalized_file)).read()
    return result

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)