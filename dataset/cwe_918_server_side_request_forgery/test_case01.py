from flask import Flask, request
import requests, socket, ipaddress
from urllib.parse import urlparse

app = Flask(__name__)

@app.route("/insecure")
def insecure_route():
    url = request.args.get("url")
    if not url:
        return "Invalid url input", 400

    return requests.get(url).text

@app.route("/secure")
def secure_route():
    url = request.args.get("url")
    if not url:
        return "Invalid url input", 400

    if url_is_public(url):
        return requests.get(url).text
    
    return "Url is not public"

def url_is_public(url):
    try:
        parsed_url_host = urlparse(url).netloc
        if not parsed_url_host:
            return False
        ip = socket.gethostbyname(parsed_url_host)
        ip = ipaddress.ip_address(ip)

        return ip.is_global
    
    except (ValueError, socket.gaierror):
        return False

if __name__ == "__main__":
    app.run(debug=True)
