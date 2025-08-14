import os
from flask import Flask, request, send_from_directory, abort
from werkzeug.utils import safe_join
from taintmonkey.taint import TaintedStr

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_filename(file):
    return TaintedStr(file.filename)


def safe_wrapper(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


@app.route("/insecure_upload", methods=["POST"])
def insecure_upload():
    if "file" not in request.files:
        return "no file uploaded", 400

    file = request.files["file"]
    filename = get_filename(file)

    return safe_wrapper(filename)


@app.route("/secure_upload", methods=["POST"])
def secure_upload():
    filename = request.args.get("filename")

    safe_path = safe_join(UPLOAD_FOLDER, filename)  # sanitizer
    if not safe_path or not os.path.isfile(safe_path):
        abort(404)
    return safe_wrapper(filename)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
