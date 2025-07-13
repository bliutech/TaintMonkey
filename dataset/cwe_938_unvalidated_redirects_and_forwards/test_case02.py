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
    
    if canonicalize (redirect_url):
        return redirect(redirect_url)

    return "Invalid redirect URL", 400

#Canonicalization
def canonicalize(input_url):
    from urllib.parse import urlparse, urljoin
    base_url = "allowed.com"

    resolve_url = urljoin(base_url, input_url)

    return urlparse(resolve_url).netloc == urlparse(base_url).netloc

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
