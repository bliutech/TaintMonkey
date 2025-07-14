from flask import Flask, request, redirect
from urllib.parse import urlparse

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

#urllib used to prevent open redirects via hostname tricks

def safe(url):
    parsed_url=urlparse(url)

    domains = {"www.allowed.com","www.safe.com", "www.secure.com"}
    hostname = parsed_url.hostname
    hostname = hostname.lower().strip('.')

    #hostname tricks like url=https://safe.com@unsafe.org won't work
    #hostname.lower().strip('.') returns only the hostname, unsafe.org ^

    return hostname in domains

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
