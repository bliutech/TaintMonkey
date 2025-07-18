from flask import request, Flask
from werkzeug.utils import secure_filename
from pathlib import Path
import os

app = Flask(__name__)
APP_DIRECTORY = app.root_path


# Source
def get_page(this_request):
    return this_request.args.get("page")


# Sanitizer
def path_within_directory(parent_directory, path):
    try:
        parent_directory_path = Path(parent_directory).resolve()
        path_path = Path(path).resolve()

        path_path.relative_to(parent_directory_path)
        return True
    except ValueError:
        return False


@app.get("/view")
def view():
    page = get_page(request)  # Source
    secure_path = secure_filename(page)  # Sanitizer
    new_path = os.path.join(APP_DIRECTORY, secure_path)  # Another Source
    if not path_within_directory(
        APP_DIRECTORY, new_path
    ):  # Not sure if this second sanitizer is necessary
        return "Path outside of directory"
    try:
        with open(new_path, "r") as f:  # Sink
            return f.read()
    except FileNotFoundError:
        return "404 FILE NOT FOUND"


@app.get("/")
def home():
    return f"""
        <a href="/view?page=user_page.txt">
            <button type="button">Default User Page</button>
        </a>
    """


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
