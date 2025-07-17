import os
from flask import Flask, request
import re

app = Flask(__name__)


def open_file_command(file):
    return "cat {}".format(file)


@app.get("/insecure")
def insecure_handler():
    file = request.args.get("file") or "example.txt"
    res = os.popen(open_file_command(file)).read()
    return res


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
