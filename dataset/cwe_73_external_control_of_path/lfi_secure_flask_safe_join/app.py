from flask import request, Flask
from werkzeug.security import safe_join

app = Flask(__name__)
ALLOWED_DIR = app.root_path


# Source
def get_page(this_request):
    return this_request.args.get("page")


@app.get("/view")
def view():
    page = get_page(request)  # Source
    safe_path = safe_join(ALLOWED_DIR, page)  # Sanitizer

    if safe_path is None:
        return "Outside of allowed directory"

    with open(page, "r") as f:  # Sink
        return f.read()


@app.get("/")
def home():
    return f"""
        <a href="/view?page=user_page.txt">
            <button type="button">Default User Page</button>
        </a>
    """


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
