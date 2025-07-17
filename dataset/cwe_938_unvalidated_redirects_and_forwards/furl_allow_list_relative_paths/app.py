from flask import Flask, request, redirect
from furl import furl

app = Flask(__name__)

ALLOW_RELATIVE_PATHS = {"/safe", "/allowed", "/secure"}


@app.route("/unvalidated_redirect", methods=["GET"])
def unvalidated_redirect():
    redirect_url = get_path()
    if not redirect_url:
        return "No URL provided", 400
<<<<<<< HEAD
    return redirect_to(redirect_url)
=======
    return redirect(redirect_url)
>>>>>>> 7f51055596869bd1e4dc22a1408bbd481c6d4308


@app.route("/validated_redirect", methods=["GET"])
def validated_redirect():
    redirect_url = get_path()
    if not redirect_url:
        return "No URL provided", 400

    if check_allow_path(redirect_url):
<<<<<<< HEAD
        return redirect_to(redirect_url)
=======
        return redirect(redirect_url)
>>>>>>> 7f51055596869bd1e4dc22a1408bbd481c6d4308

    return "Invalid redirect URL", 400


def get_path():
    return request.args.get("path")

<<<<<<< HEAD
def redirect_to(url):
    return redirect(url)
=======
>>>>>>> 7f51055596869bd1e4dc22a1408bbd481c6d4308

def check_allow_path(path):
    # furl used to check for allowable relative paths
    parsed_url = furl(path)

    return (
        (parsed_url.scheme == "" or parsed_url.scheme == None)
        and (parsed_url.host == "" or parsed_url.host == None)
        and str(parsed_url.path) in ALLOW_RELATIVE_PATHS
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
