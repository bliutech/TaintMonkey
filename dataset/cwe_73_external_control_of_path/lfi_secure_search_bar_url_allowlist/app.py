from flask import request, Flask, redirect, url_for

app = Flask(__name__)

allowlist = ["user_page.txt"]


# Source
def get_page_post(this_request):
    return this_request.form.get("query")


# Source
def get_page(this_request):
    return this_request.args.get("page")


# Sanitizer
def page_is_allowed(page):
    return page in allowlist


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

    if not page_is_allowed(page):  # Sanitizer
        return "Page not allowed"

    return redirect(url_for("view", page=page))  # FAKE SINK


@app.get("/view")
def view():
    page = get_page(request)  # Source

    if not page_is_allowed(page):  # Sanitizer
        return "Page not allowed - Stop trying to URL inject >:("

    with open(page, "r") as f:  # Sink
        return f.read()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
