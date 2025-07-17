from flask import Flask, request
import requests
from urllib.parse import urlparse

app = Flask(__name__)

DENY_LIST = {"www.malicious.com", "www.evil.com", "www.unsafe.com"}

@app.route("/insecure")
def insecure_route():
    url = request.args.get("url")
    if not url:
        return "Invalid url input", 400

    return requests.get(url).text

@app.route("/secure")
def secure_route():
    url = request.args.get("url")
    if not url:
        return "Invalid url input", 400

    if url_is_allowed(url):
        return requests.get(url).text
    
    return "Url is not allowed"

def url_is_allowed(url):
# urllib used to check for denyable links
    parsed_url = urlparse(url)

    return (
        (parsed_url.scheme == "http" or parsed_url.scheme == "https")
        and parsed_url.netloc not in DENY_LIST
    )

if __name__ == "__main__":
    app.run(debug=True)