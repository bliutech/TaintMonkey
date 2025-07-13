import os
from flask import Flask, request

app = Flask(__name__)


def open_file_command(file):
    # Intentionally vulnerable - directly interpolates the file parameter
    return "cat {}".format(file)


@app.get("/insecure")
def insecure_handler():
    file = request.args.get("file") or "example.txt"
    # Intentionally vulnerable - passes the raw command to shell
    command = open_file_command(file)
    res = os.popen(command).read()
    return res


if __name__ == "__main__":
    if not os.path.exists("example.txt"):
        with open("example.txt", "w") as f:
            f.write("This is testcase7 insecure example file\n")
    
    app.run(host="0.0.0.0", port=8080) 