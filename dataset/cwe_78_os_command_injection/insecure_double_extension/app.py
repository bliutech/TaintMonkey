import os
from flask import Flask, request
from urllib.parse import unquote

app = Flask(__name__)


def open_file_command(file):
    return "cat {}".format(file)


@app.get("/insecure")
def insecure_handler():
    raw_file = request.args.get("file") or "example.txt"

    decoded_file = unquote(unquote(raw_file))

    result = os.popen(open_file_command(decoded_file)).read()
    return result


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
