import os
from flask import Flask, request, send_from_directory, abort
from werkzeug.utils import safe_join

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/insecure_upload")
def insecure_upload():
    filename = request.args.get("filename")
    file_path = os.path.join(UPLOAD_FOLDER, filename)

    if not os.path.exists(file_path):
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, filename)


@app.route("/secure_upload")
def secure_upload():
    filename = request.args.get("filename")

    safe_path = safe_join(UPLOAD_FOLDER, filename)  # sanitizer
    if not safe_path or not os.path.isfile(safe_path):
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, filename)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
