import os
from flask import Flask, request, abort

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def filename_is_allowed(filename):
    return filename in ALLOWED_PAGES


ALLOWED_PAGES = {"notes.txt", "info.txt"}


@app.get("/insecure_read")
def insecure_read():
    filename = request.args.get("filename")
    if not filename:
        return "Filename required", 400

    path = os.path.join(UPLOAD_FOLDER, filename)
    try:
        with open(path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return "File not found", 404


@app.get("/secure_read")
def secure_read():
    filename = request.args.get("filename")

    if not filename:
        return "filename required", 400

    if not filename_is_allowed(filename):  # sanitizer
        return "page not allowed", 403

    path = os.path.join(UPLOAD_FOLDER, filename)
    try:
        with open(path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return "File not found", 40


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
