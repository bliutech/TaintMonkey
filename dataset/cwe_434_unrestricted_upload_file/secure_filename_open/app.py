import os
from flask import Flask, request
from werkzeug.utils import secure_filename
from taintmonkey.taint import TaintedStr

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_filename(file):
    from taintmonkey.taint import TaintedStr

    return TaintedStr(file.filename)


def safe_wrapper(path, file):
    with open(path, "wb") as f:
        f.write(file.read())


@app.post("/insecure_upload")
def insecure_upload():
    if "file" not in request.files:
        return "No file part", 400

    file = request.files["file"]
    if get_filename(file) == "":
        return "No selected file", 400

    filename = get_filename(file)

    path = TaintedStr(os.path.join(UPLOAD_FOLDER, filename))

    safe_wrapper(path, file)
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
    safe_wrapper(path, file)

    return f"File {filename} uploaded securely."


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
