from flask import Flask, request, redirect
from yarl import URL

app = Flask(__name__)

DENY_LIST = {"www.malicious.com", "www.evil.com", "www.unsafe.com"}


@app.route("/unvalidated_redirect", methods=["GET"])
def unvalidated_redirect():
    redirect_url = get_url()
    if not redirect_url:
        return "No URL provided", 400
    redirect_to(redirect_url)


@app.route("/validated_redirect", methods=["GET"])
def validated_redirect():
    redirect_url = get_url()

    if not redirect_url:
        return "No URL provided", 400

    if check_deny_list(redirect_url):
        redirect_to(redirect_url)

    return "Invalid redirect URL", 400


def get_url():
    return request.args.get("url")


def redirect_to(url):
    return redirect(url)


def check_deny_list(url):
    # yarl used to check for denyable domains
    parsed_url = URL(url)

    return (
        parsed_url.scheme == "http"
        or parsed_url.scheme == "https"
        and parsed_url.host not in DENY_LIST
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
