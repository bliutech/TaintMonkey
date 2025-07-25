import os
from flask import Flask, request, send_file, abort
from werkzeug.utils import safe_join

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.post("/insecure_upload")
def insecure_upload():
    uploaded_file = request.files.get("file")
    if not uploaded_file or uploaded_file.filename == "":
        return "No file uploaded", 400

    filename = uploaded_file.filename
    path = os.path.join(UPLOAD_FOLDER, filename)
    uploaded_file.save(path)
    return f"Insecurely saved to {path}"


@app.get("/insecure_download")
def insecure_download():
    filename = request.args.get("filename")
    if not filename:
        return "Filename required", 400

    path = os.path.join(UPLOAD_FOLDER, filename)
    try:
        return send_file(path)
    except FileNotFoundError:
        return "File not found", 404


@app.get("/secure_download")
def secure_download():
    filename = request.args.get("filename")
    if not filename:
        return "Filename required", 400

    path = safe_join(UPLOAD_FOLDER, filename)  # sanitizer
    if not path or not os.path.isfile(path):
        return "File not found or unsafe path", 404

    return send_file(path)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
