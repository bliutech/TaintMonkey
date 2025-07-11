#https://www.freeformatter.com/html-escape.html

from flask import Flask, request
import html

app = Flask(__name__)

@app.route("/form_insecure")
def form():
    return '''
    <form action="/submit_insecure" method="post">
    <input type="text" name="username" placeholder="Username">
    <input type="submit"
    '''

@app.post("/submit_insecure")
def submit_insecure():
    username = request.form["username"]
    return f"Hello, {username}!"

@app.route("/form_secure")
def form_secure():
    return '''
    <form action="/submit_secure" method="post">
    <input type="text" name="username" placeholder="Username">
    <input type="submit"
    '''
@app.post("/submit_secure")
def submit_secure():
    username = request.form["username"]
    username = html.escape(username)
    return f"Hello, {username}!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

    