from flask import request, Flask
from pathlib import Path

app = Flask(__name__)
APP_DIRECTORY = app.root_path


# Source
def get_page(this_request):
    return this_request.args.get("page")


@app.get("/view")
def view():
    page = get_page(request)  # Source
    new_path = Path(APP_DIRECTORY) / page  # Another Source
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
