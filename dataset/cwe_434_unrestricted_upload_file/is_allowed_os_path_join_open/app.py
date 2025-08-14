import os
from flask import Flask, request, abort
from taintmonkey.taint import TaintedStr

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def safe_wrapper(path):
    try:
        with open(path, "r") as f:
            return f.read()
    except FileNotFoundError:
        abort(404, "File not found")


def get_filename(file):
    if isinstance(file, TaintedStr):
        return file
    return TaintedStr(file)


def filename_is_allowed(filename):
    return filename in ALLOWED_PAGES


ALLOWED_PAGES = {"notes.txt", "info.txt"}


@app.get("/insecure_read")
def insecure_read():
    filename = request.args.get("filename")
    if not filename:
        return "Filename required", 400

    filename = get_filename(filename)

    path = TaintedStr(os.path.join(UPLOAD_FOLDER, filename))
    return safe_wrapper(path)


@app.get("/secure_read")
def secure_read():
    filename = request.args.get("filename")

    if not filename:
        return "filename required", 400

    if not filename_is_allowed(filename):  # sanitizer
        return "page not allowed", 403

    filename = get_filename(filename)

    path = os.path.join(UPLOAD_FOLDER, filename)
    return safe_wrapper(path)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
