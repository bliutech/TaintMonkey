from flask import Flask, request, redirect
from urllib.parse import urlparse

app = Flask(__name__)


@app.route("/unvalidated_redirect", methods=["GET"])
def unvalidated_redirect():
    redirect_url = request.args.get("path")
    if not redirect_url:
        return "No URL provided", 400
    return redirect(redirect_url)


@app.route("/validated_redirect", methods=["GET"])
def validated_redirect():
    redirect_url = request.args.get("path")

    if not redirect_url:
        return "No URL provided", 400

    if safe(redirect_url):
        return redirect(redirect_url)

    return "Invalid redirect URL", 400


# urllib used to check for allowable relative-url paths
# doesn't allow redirect to other domains; only relative, safe, paths


def safe(path):
    parsed_url = urlparse(path)

    paths = {"/safe", "/allowed", "/secure"}

    return (
        (parsed_url.scheme == "" or parsed_url.scheme == None)
        and (parsed_url.netloc == "" or parsed_url.netloc == None)
        and parsed_url.path in paths
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
