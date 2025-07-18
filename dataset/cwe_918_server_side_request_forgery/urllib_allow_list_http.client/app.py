from flask import Flask, request
import http.client
from urllib.parse import urlparse

app = Flask(__name__)

ALLOW_LIST = {"www.allowed.com", "www.safe.com", "www.secure.com"}
ALLOW_PATHS = {"/safe", "/allowed", "/secure", "", "/"}


@app.route("/insecure")
def insecure_route():
    url = request.args.get("url")
    if not url:
        return "Invalid url input", 400
    url = urlparse(url)
    connection = http.client.HTTPConnection(url.netloc, url.port)
    connection.request("GET", url.path)
    return connection.getresponse()


@app.route("/secure")
def secure_route():
    url = request.args.get("url")
    if not url:
        return "Invalid url input", 400
    if check_allow_list(url):
        url = urlparse(url)
        connection = http.client.HTTPConnection(url.netloc, url.port)
        connection.request("GET", url.path)
        return connection.getresponse()
    return "Url is not allowed"


def check_allow_list(url):
    # urllib used to check for allowable links
    parsed_url = urlparse(url)
    return (
        (parsed_url.scheme == "http" or parsed_url.scheme == "https")
        and parsed_url.netloc in ALLOW_LIST
        and parsed_url.path in ALLOW_PATHS
    )


if __name__ == "__main__":
    app.run(debug=True)
