import os
import requests
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"
FORWARD_URL = "http://localhost:8080/forward"

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


@app.post("/insecure_upload")
def insecure_upload():
    if "file" not in request.files:
        return "no file", 400

    file = request.files["file"]
    filename = file.filename

    files = {"file": (filename, file.stream, file.content_type)}
    response = requests.post(FORWARD_URL, files=files)

    return f"forwarded with {response.status_code}"


@app.post("/secure_upload")
def secure_upload():
    if "file" not in request.files:
        return "no file", 400

    file = request.files["file"]
    filename = secure_filename(file.filename)  # sanitizer

    if not filename:
        return "invalid name", 400

    files = {"file": (filename, file.stream, file.mimetype)}
    resp = requests.post(FORWARD_URL, files=files)

    return f"securely forwarded with {resp.status_code}"


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
