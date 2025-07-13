import re
import os
import shlex
from flask import Flask, request

app = Flask(__name__)

def open_file_command(file):
    return "cat {}".format(file)


def is_safe_path(path):
    return re.match(r"^[a-zA-Z0-9_.-]+$", path)

def is_safe_command(command):
    return '&&' not in command


@app.get("/secure")
def secure_handler():
    file = request.args.get("file") or "example.txt"

    if not is_safe_path(file):
        return "Invalid file path"

    command = open_file_command(file)
    
    if not is_safe_command(command):
        return "Invalid command detected: && operator not allowed"

    safe_file = shlex.quote(file)
    safe_command = "cat {}".format(safe_file)
    
    res = os.popen(safe_command).read()
    return res

if __name__ == "__main__":
    if not os.path.exists("example.txt"):
        with open("example.txt", "w") as f:
            f.write("This is an example file.\n")
    
    app.run(host="0.0.0.0", port=8080)
