from flask import request, Flask
from werkzeug.security import safe_join

app = Flask(__name__)
ALLOWED_DIR = app.root_path


# Source
def get_page(this_request):
    return this_request.form.get("query")


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
    page = get_page(request)  # Source
    safe_path = safe_join(ALLOWED_DIR, page)  # Sanitizer

    if safe_path is None:
        return "Outside of allowed directory"

    try:
        with open(page, "r") as f:  # Sink
            return f.read()
    except FileNotFoundError:
        return "404 FILE NOT FOUND"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
