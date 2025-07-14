from flask import Flask, request, redirect
from urllib.parse import urlparse
import socket, ipaddress

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

#Prevents redirects to internal IPs
#addreses SSRF

def safe(url):
    
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    ip = socket.gethostbyname(hostname)

    return ipaddress.ip_address(ip).is_global

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
