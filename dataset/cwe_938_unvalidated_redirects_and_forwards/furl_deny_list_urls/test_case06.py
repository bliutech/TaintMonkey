from flask import Flask, request, redirect
from furl import furl

app = Flask(__name__)

DENY_LIST = {"www.malicious.com", "www.evil.com", "www.unsafe.com"}


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

    if safe(redirect_url):
        return redirect(redirect_url)

    return "Invalid redirect URL", 400


# furl used to check for denyable domains


def safe(url):
    parsed_url = furl(url)

    return (
        parsed_url.scheme == "http" or parsed_url.scheme == "https"
    ) and parsed_url.netloc not in DENY_LIST


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
