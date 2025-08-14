import os
from flask import Flask, request
import magic
from taintmonkey.taint import TaintedStr

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def safe_wrapper(uploaded_file, filepath):
    uploaded_file.save(filepath)


def get_filename(file):
    return TaintedStr(file.filename)


@app.post("/insecure_upload")
def insecure_upload():
    uploaded_file = request.files.get("file")
    if not uploaded_file or uploaded_file.filename == "":
        return "No file uploaded", 400

    filename = get_filename(uploaded_file)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    filepath = TaintedStr(filepath)

    safe_wrapper(uploaded_file, filepath)
    return f"Insecurely saved to {filepath}"


@app.post("/secure_upload")
def secure_upload():
    uploaded_file = request.files.get("file")
    if not uploaded_file or uploaded_file.filename == "":
        return "No file uploaded", 400

    # sanitizer
    file_bytes = uploaded_file.read(2048)
    uploaded_file.seek(0)
    mime_type = magic.from_buffer(file_bytes, mime=True)

    allowed_types = ["image/jpeg", "image/png"]
    if mime_type not in allowed_types:
        return f"File type {mime_type} not allowed", 400

    filepath = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
    safe_wrapper(uploaded_file, filepath)
    return f"Securely saved to {filepath}"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
