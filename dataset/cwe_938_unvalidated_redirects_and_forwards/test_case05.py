from flask import Flask, request, redirect
import urllib.parse

app = Flask(__name__)

@app.route("/unvalidated_redirect", methods=["GET"])
def unvalidated_redirect():
    redirect_url = request.args.get("url")
    if not redirect_url:
        return "No URL provided", 400
    return redirect(redirect_url)

@app.route("/validated_redirect", methods=["GET"])
def validated_redirect():
    redirect_url = request.args.get("url")

    if not redirect_url:
        return "No URL provided", 400
    
    if regex(redirect_url):
        return redirect(redirect_url)

    return "Invalid redirect URL", 400

#Regex validation
def regex(input_url):
    import re

    regex_pattern = re.compile(r'^\/[a-zA-Z0-9_\-\/]*$')

    return bool(regex_pattern.match(input_url))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
