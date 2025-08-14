import os
import requests
from flask import Flask, request
from werkzeug.utils import secure_filename
from taintmonkey.taint import TaintedStr

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"
FORWARD_URL = "http://localhost:8080/forward"

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


def get_filename(file):
    return TaintedStr(file.filename)


def safe_wrapper(filename, file_stream, content_type):
    files = {"file": (filename, file_stream, content_type)}
    response = requests.post(FORWARD_URL, files=files)
    return response.status_code


@app.post("/insecure_upload")
def insecure_upload():
    if "file" not in request.files:
        return "no file", 400

    file = request.files["file"]
    filename = get_filename(file)

    status = safe_wrapper(filename, file.stream, file.content_type)

    return f"forwarded with {status}"


@app.post("/secure_upload")
def secure_upload():
    if "file" not in request.files:
        return "no file", 400

    file = request.files["file"]
    filename = secure_filename(file.filename)  # sanitizer

    if not filename:
        return "invalid name", 400

    status = safe_wrapper(filename, file.stream, file.mimetype)

    return f"securely forwarded with {status}"


@app.post("/forward")
def forward_receiver():
    if "file" not in request.files:
        return "no file received", 400
    file = request.files["file"]
    filename = file.filename
    print(f"Forwarded file received: {filename}")
    return "forwarded file received", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
