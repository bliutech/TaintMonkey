from flask import Flask, request
import requests
from yarl import URL

app = Flask(__name__)

DENY_LIST = {"www.malicious.com", "www.evil.com", "www.unsafe.com"}


@app.route("/insecure")
def insecure_route():
    url = get_url()
    if not url:
        return "Invalid url input", 400
    return http_request(url)


@app.route("/secure")
def secure_route():
    url = get_url()
    if not url:
        return "Invalid url input", 400
    if check_deny_list(url):
        return http_request(url)
    return "Url is not allowed"


def check_deny_list(url):
    # yarl used to check for denyable links
    parsed_url = URL(url)
    return (
        parsed_url.scheme == "http" or parsed_url.scheme == "https"
    ) and parsed_url.host not in DENY_LIST


def get_url():
    return request.args.get("url")


def http_request(url):
    return requests.get(url).text


if __name__ == "__main__":
    app.run(debug=True)
