from flask import Flask, request, redirect
from urllib.parse import urlparse

app = Flask(__name__)

ALLOW_RELATIVE_PATHS = {"/safe", "/allowed", "/secure"}


@app.route("/unvalidated_redirect", methods=["GET"])
def unvalidated_redirect():
    redirect_url = get_path()
    if not redirect_url:
        return "No URL provided", 400
    return redirect_to(redirect_url)


@app.route("/validated_redirect", methods=["GET"])
def validated_redirect():
    redirect_url = get_path()
    if not redirect_url:
        return "No URL provided", 400

    if check_allow_path(redirect_url):
        return redirect_to(redirect_url)

    return "Invalid redirect URL", 400


def get_path():
    return request.args.get("path")

def redirect_to(url):
    return redirect(url)


def check_allow_path(path):
    # urllib used to check for allowable relative-url paths
    parsed_url = urlparse(path)

    return (
        (parsed_url.scheme == "" or parsed_url.scheme == None)
        and (parsed_url.netloc == "" or parsed_url.netloc == None)
        and parsed_url.path in ALLOW_RELATIVE_PATHS
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
