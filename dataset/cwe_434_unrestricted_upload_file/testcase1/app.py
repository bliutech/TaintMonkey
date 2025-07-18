import os
from flask import Flask, request, abort, send_from_directory
from werkzeug.datastructures import FileStorage
import re


app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads/"


os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


def get_filename(file):
    return file.filename


def safe_wrapper(file, filename):
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))


def is_safe_filename(filename):
    allowed_extensions = {"jpg", "png", "gif"}
    return (
        filename.count(".") == 1
        and filename.rsplit(".", 1)[1].lower() in allowed_extensions
    )


@app.route("/insecure/upload", methods=["POST"])
def insecure_upload():
    if "file" not in request.files:
        return "No file part", 400

    file = request.files["file"]
    if get_filename(file) == "":
        return "No selected file", 400

    filename = get_filename(file)
    print(f"{filename}")

    if is_safe_filename(filename):
        safe_wrapper(file, filename)
        print("file uploaded successfully")
        return f"File uploaded successfully"
    else:
        return "Only image files are allowed", 400


@app.route("/secure/upload", methods=["POST"])
def secure_upload():
    if "file" not in request.files:
        return "No file part", 400

    file = request.files["file"]
    filename = get_filename(file)
    if filename == "":
        return "No selected file", 400

    filename = get_filename(file)

    if filename is not None and filename.count(".") > 1:
        return "Multiple extensions not allowed", 400

    allowed_extensions = {"jpg", "png", "gif"}
    if (
        not filename
        or "." not in filename
        or filename.rsplit(".", 1)[1].lower() not in allowed_extensions
    ):
        return "Only image files are allowed", 400

    file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    return f"File uploaded successfully"


@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
