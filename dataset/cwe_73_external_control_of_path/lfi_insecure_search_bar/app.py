from flask import request, Flask

app = Flask(__name__)

#Source
def get_page(this_request):
    return this_request.form.get("query")

@app.get("/")
def home():
    return f'''
        <form action="/search" method="get">
            <button type="submit">To Search</button>
        </form>
    '''

@app.get("/search")
def search_get():
    return f'''
        <form method="post">
            <h2>File Search Up</h2>
            Query: <input name="query"><br>
            <input type="submit" value="Search">
        </form>
    '''

@app.post("/search")
def search_post():
    page = get_page(request) # Source
    with open(page, "r") as f: #Sink
        return f.read()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)