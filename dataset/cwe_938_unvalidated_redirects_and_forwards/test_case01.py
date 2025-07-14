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

#urllib used to check for allowable redirect links
#checks for an entire link and whether or not it is secure

def safe(url):
    parsed_url=urlparse(url)

    domains = {"www.allowed.com","www.safe.com", "www.secure.com"}
    paths = {"/safe", "/allowed", "/secure", "", "/"} 
    ## "" and "/" cases --> if no path is entered

    return (    
        (parsed_url.scheme == "http" or parsed_url.scheme == "https") and
        parsed_url.netloc in domains and 
        parsed_url.path in paths
    )

    #checks scheme for http or https
    #checks domain for allowable domains
    #checks paths for allowable paths within those domains

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
