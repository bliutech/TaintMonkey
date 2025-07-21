import os
import re
from flask import Flask, request, redirect, url_for, send_from_directory

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads/"

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


@app.route("/insecure/upload", methods=["POST"])
def insecure_upload():
    if "file" not in request.files:
        return "No file part", 400

    file = request.files["file"]

    if file.filename == "":
        return "No selected file", 400

    filename = file.filename

    # can't block everything
    blacklisted_extensions = ["php", "php3", "php4", "php5", "phtml"]

    if "." in filename:
        extension = filename.rsplit(".", 1)[1].lower()

        if extension in blacklisted_extensions:
            return f"File type not allowed", 400

        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        return redirect(url_for("uploaded_file", filename=filename))
    else:
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        return redirect(url_for("uploaded_file", filename=filename))


@app.route("/secure/upload", methods=["POST"])
def secure_upload():
    if "file" not in request.files:
        return "No file part", 400

    file = request.files["file"]

    if file.filename == "":
        return "No selected file", 400

    filename = file.filename

    # only allows these types (safer types)
    allowed_extensions = {"jpg", "jpeg", "png", "gif", "txt", "pdf"}

    if "." not in filename:
        return "Files must have an extension", 400

    extension = filename.rsplit(".", 1)[1].lower()
    if extension not in allowed_extensions:
        return (
            f"Only the following file types are allowed: {', '.join(allowed_extensions)}",
            400,
        )

    if extension in ["jpg", "jpeg", "png", "gif"]:
        file_content = file.read(1024)
        file.seek(0)

        is_valid_image = False

        # jpex mbytes
        if extension in ["jpg", "jpeg"] and file_content.startswith(b"\xff\xd8\xff"):
            is_valid_image = True

        # png mbytes
        elif extension == "png" and file_content.startswith(
            b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"
        ):
            is_valid_image = True

        # gif signatures
        elif extension == "gif" and (
            file_content.startswith(b"GIF87a") or file_content.startswith(b"GIF89a")
        ):
            is_valid_image = True

        if not is_valid_image:
            return "File content does not match the extension", 400

    file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    return redirect(url_for("uploaded_file", filename=filename))


@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
