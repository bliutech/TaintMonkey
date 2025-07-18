import os
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    send_from_directory,
    render_template,
)

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

    if (
        filename.endswith(".jpg")
        or filename.endswith(".png")
        or filename.endswith(".gif")
    ):
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        return redirect(url_for("uploaded_file", filename=filename))
    else:
        return "File type not allowed.", 400


@app.route("/secure/upload", methods=["POST"])
def secure_upload():
    if "file" not in request.files:
        return "No file part", 400

    file = request.files["file"]

    if file.filename == "":
        return "No selected file", 400

    filename = file.filename

    allowed_extensions = {"jpg", "jpeg", "png", "gif"}
    if (
        "." not in filename
        or filename.rsplit(".", 1)[1].lower() not in allowed_extensions
    ):
        return "Only image files are allowed", 400

    file_content = file.read(1024)
    file.seek(0)

    is_valid_image = False

    # checks the "magic byte" to validate the image type
    # jpeg
    if file_content.startswith(b"\xff\xd8\xff"):
        is_valid_image = True

    # png
    elif file_content.startswith(b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a"):
        is_valid_image = True

    # gif
    elif file_content.startswith(b"GIF87a") or file_content.startswith(b"GIF89a"):
        is_valid_image = True

    if not is_valid_image:
        return "File content is not an allowed image types", 400

    file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    return redirect(url_for("uploaded_file", filename))


@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
