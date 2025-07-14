from flask import Flask, request, redirect
import requests


app = Flask(__name__)

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
    
    if safe (redirect_url):
        return redirect(redirect_url)

    return "Invalid redirect URL", 400

#requests used to prevent all automatic redirects
#only allows URLs that respond without redirects

def safe(url):
    redirect = requests.get(url, allow_redirects=False)
    return redirect.status_code not in (301, 302, 307, 308)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
