from flask import request, Flask, redirect, url_for
from werkzeug.security import safe_join

app = Flask(__name__)
ALLOWED_DIR = app.root_path


# Source
def get_page_post(this_request):
    return this_request.form.get("query")


# Source
def get_page(this_request):
    return this_request.args.get("page")


@app.get("/")
def home():
    return f"""
        <form action="/search" method="get">
            <button type="submit">To Search</button>
        </form>
    """


@app.get("/search")
def search_get():
    return f"""
        <form method="post">
            <h2>File Search Up</h2>
            Query: <input name="query"><br>
            <input type="submit" value="Search">
        </form>
    """


@app.post("/search")
def search_post():
    page = get_page_post(request)  # Source
    safe_path = safe_join(ALLOWED_DIR, page)  # Sanitizer

    if safe_path is None:
        return "Outside of allowed directory"

    return redirect(url_for("view", page=safe_path))  # FAKE SINK


@app.get("/view")
def view():
    page = get_page(request)  # Source
    try:
        with open(page, "r") as f:  # Sink
            return f.read()
    except FileNotFoundError:
        return "404 FILE NOT FOUND"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
