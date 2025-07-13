from flask import Flask, request, redirect
import urllib.parse

app = Flask(__name__)

@app.route("/unvalidated_redirect", methods=["GET"])
def unvalidated_redirect():
    redirect_url = request.args.get("url")
    if not redirect_url:
        return "No URL provided", 400
    return redirect(redirect_url)

@app.route("/validated_redirect", methods=["GET"])
def validated_redirect():
    redirect_token = request.args.get("url")

    if not redirect_token:
        return "No URL token provided", 400
    
    if is_token (redirect_token):
        return redirect(token_list[redirect_token])

    return "Invalid redirect token", 400

token_list = {
        "allowed": "/allowed",
        "safe": "/safe",
        "home": "/home"
    }

#Token Validation
def is_token(input_token):

    if input_token in token_list:
        return True 
    
    return False

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
