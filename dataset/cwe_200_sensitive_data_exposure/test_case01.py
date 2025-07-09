from flask import Flask, request
import hashlib

app = Flask(__name__)

@app.post("/insecure_register")
def register_insecure_ssnum ():
    ssnum = request.args.get("ssnum")
    if ssnum is None or "":
        return ("Please enter a valid SSN", 400)
    else:
        app.logger.info(f"SSN entered: {ssnum}")
        return ("SS Number: " + ssnum, 200)

@app.post("/secure_register")
def register_secure_ssnum():
    ssnum = request.args.get("ssnum")
    if ssnum is None or "":
        return ("Please enter a valid SSN", 400)
    else:
        anon = hashlib.sha256(ssnum.encode()).hexdigest()
        app.logger.info(f"SSN entered: {anon}")
        return ("SS Number: " + anon, 200)


if (__name__ == "__main__"):
    app.run(host="0.0.0.0", port=8080)

