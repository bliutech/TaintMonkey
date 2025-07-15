from flask import Flask, request, redirect
from urllib.parse import urlparse


app = Flask(__name__)

ALLOW_LIST = {"www.allowed.com", "www.safe.com", "www.secure.com"}
ALLOW_PATHS = {"/safe", "/allowed", "/secure", "", "/"}

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


# urllib used to check for allowable redirect links
# checks for an entire link and whether or not it is secure


def safe(url):
    parsed_url = urlparse(url)

    return (
        (parsed_url.scheme == "http" or parsed_url.scheme == "https")
        and parsed_url.netloc in ALLOW_LIST
        and parsed_url.path in ALLOW_PATHS
    )

    # checks scheme for http or https
    # checks domain for allowable domains
    # checks paths for allowable paths within those domains


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
