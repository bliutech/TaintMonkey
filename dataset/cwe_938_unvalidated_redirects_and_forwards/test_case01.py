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
    
    if safe (redirect_url):
        return redirect(redirect_url)

    return "Invalid redirect URL", 400

#urllib used to sanitize url scheme
def safe(url):

    from urllib.parse import urlparse

    parsed_url=urlparse(url)

    return parsed_url.scheme == "http" or parsed_url.scheme == "https"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
