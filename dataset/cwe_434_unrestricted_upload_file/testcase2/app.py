import os
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.post("/insecure_upload")
def insecure_upload():
    if "file" not in request.files:
        return "No file part", 400

    file = request.files["file"]
    if file.filename == "":
        return "No selected file", 400

    path = os.path.join(UPLOAD_FOLDER, file.filename)
    with open(path, "wb") as f:
        f.write(file.read())

    return f"File {file.filename} uploaded insecurely"


@app.post("/secure_upload")
def secure_upload():
    if "file" not in request.files:
        return "No file part", 400

    file = request.files["file"]
    if file.filename == "":
        return "No selected file", 400

    filename = secure_filename(file.filename)  # sanitizer
    path = os.path.join(UPLOAD_FOLDER, filename)
    with open(path, "wb") as f:
        f.write(file.read())

    return f"File {filename} uploaded securely."


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
