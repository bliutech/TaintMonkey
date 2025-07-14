from flask import Flask, request, redirect

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
    
    if safe(redirect_url):
        return redirect(redirect_url)

    return "Invalid redirect URL", 400

#urllib used to sanitize url path
def safe(url):
    from furl import furl
    furled = furl (url)

    safe_paths = {"safe", "secure", "allowed"}
    path_segments = furled.path.segments
    ##returns list of paths
    ##furl(bliu.com/hi/benson) --> {"hi","benson"}

    for path in path_segments:
        if path in safe_paths:
            return True
        
    return False

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
