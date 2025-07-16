import os
import re
from flask import Flask, request
from urllib.parse import unquote

app = Flask(__name__)

def open_file_command(file):
    return "cat {}".format(file)


def is_safe_path(path):
    return re.fullmatch(r"^[a-zA-Z0-9_.-]+$", path)


@app.get("/secure")
def secure_handler():
    raw_file = request.args.get("file") or "example.txt"

    decoded_file = unquote(unquote(raw_file))

    if not is_safe_path(decoded_file):
        return "Invalid file path", 400

    result = os.popen(open_file_command(decoded_file)).read()
    return result


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)