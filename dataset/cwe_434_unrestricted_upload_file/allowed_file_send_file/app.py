import os
from flask import Flask, request, abort, send_file

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads/"

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


def allowed_file(filename):
    allowed_extensions = {"jpg", "png", "gif"}
    return (
        filename.count(".") == 1
        and filename.rsplit(".", 1)[1].lower() in allowed_extensions
    )


@app.post("/insecure/download")
def insecure_download():
    filename = request.form.get("file")
    if not filename:
        return "no file", 400

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

    if not os.path.isfile(file_path):
        return "file not found", 404

    return send_file(file_path)


@app.post("/secure/download")
def secure_download():
    filename = request.form.get("file")
    if not filename:
        return "no file", 400

    if not allowed_file(filename):
        return "invalid file", 400

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

    if not os.path.isfile(file_path):
        return "file not found", 404

    return send_file(file_path)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
