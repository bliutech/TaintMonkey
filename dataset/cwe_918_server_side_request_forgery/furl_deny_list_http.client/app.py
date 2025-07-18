from flask import Flask, request
import http.client
from furl import furl

app = Flask(__name__)

DENY_LIST = {"www.malicious.com", "www.evil.com", "www.unsafe.com"}


@app.route("/insecure")
def insecure_route():
    url = request.args.get("url")
    if not url:
        return "Invalid url input", 400
    url = furl(url)
    connection = http.client.HTTPConnection(url.host, url.port)
    connection.request("GET", url.pathstr)
    return connection.getresponse()


@app.route("/secure")
def secure_route():
    url = request.args.get("url")
    if not url:
        return "Invalid url input", 400
    if check_deny_list(url):
        url = furl(url)
        connection = http.client.HTTPConnection(url.host, url.port)
        connection.request("GET", url.pathstr)
        return connection.getresponse()
    return "Url is not allowed"


def check_deny_list(url):
    # furl used to check for denyable links
    parsed_url = furl(url)
    return (
        parsed_url.scheme == "http" or parsed_url.scheme == "https"
    ) and parsed_url.host not in DENY_LIST


if __name__ == "__main__":
    app.run(debug=True)
