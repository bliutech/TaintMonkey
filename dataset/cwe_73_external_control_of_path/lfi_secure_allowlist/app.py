from flask import request, Flask

app = Flask(__name__)

allowlist = ["user_page.txt"]

#Source
def get_page(this_request):
    return this_request.args.get("page")

#Sanitizer
def page_is_allowed(page):
    return page in allowlist

@app.get("/view")
def view():
    page = get_page(request) # Source

    if not page_is_allowed(page): #Sanitizer
        return "Page not allowed"

    with open(page, "r") as f: #Sink
        return f.read()

@app.get("/")
def home():
    return f'''
        <a href="/view?page=user_page.txt">
            <button type="button">Default User Page</button>
        </a>
    '''

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)