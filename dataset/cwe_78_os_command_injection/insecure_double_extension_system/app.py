import os
import re
from flask import Flask, request
from urllib.parse import unquote

app = Flask(__name__)


def open_file_command(file):
    return f"cat {file}"


@app.get("/insecure")
def insecure_handler():
    raw_file = request.args.get("file") or "example.txt"

    # does not validate
    decoded_file = unquote(unquote(raw_file))

    # just create an exit code
    exit_code = os.system(open_file_command(decoded_file))

    if exit_code == 0:
        return "Command executed successfully"
    else:
        return f"Command exit code failed", 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
