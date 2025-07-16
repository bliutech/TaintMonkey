from flask import Flask, request, redirect
from yarl import URL

app = Flask(__name__)

ALLOW_LIST = {"www.allowed.com", "www.safe.com", "www.secure.com"}
ALLOW_PATHS = {"/safe", "/allowed", "/secure", "", "/"}
@app.route("/unvalidated_redirect", methods=["GET"])
def unvalidated_redirect():
    redirect_url = get_url()
    if not redirect_url:
        return "No URL provided", 400
    return redirect(redirect_url)
@app.route("/validated_redirect", methods=["GET"])
def validated_redirect():
    redirect_url = get_url()

    if not redirect_url:
        return "No URL provided", 400

    if check_allow_list(redirect_url):
        return redirect(redirect_url)

    return "Invalid redirect URL", 400
def get_url():
    return request.args.get("url")
def check_allow_list(url):
# yarl used to check for allowable urls
    parsed_url = URL(url)

    return (
        (parsed_url.scheme == "http" or parsed_url.scheme == "https")
        and parsed_url.host in ALLOW_LIST
        and parsed_url.path in ALLOW_PATHS
    )
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)