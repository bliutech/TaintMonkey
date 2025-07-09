from flask import Flask, request
import hashlib

app = Flask(__name__)

@app.post("/insecure_register")
def register_insecure_SSNum ():
    ssNum = request.args.get("ssNum")
    if ssNum is None or "":
        return ("Please enter a valid SSN", 400)
    else:
        app.logger.info(f"SSN entered: {ssNum}")
        return ("SS Number: " + ssNum, 200)

@app.post("/secure_register")
def register_secure_SSNum():
    ssNum = request.args.get("ssNum")
    if ssNum is None or "":
        return ("Please enter a valid SSN", 400)
    else:
        anon = hashlib.sha256(ssNum.encode()).hexdigest()
        app.logger.info(f"SSN entered: {anon}")
        return ("SS Number: " + anon, 200)


if (__name__ == "__main__"):
    app.run(host="0.0.0.0", port=8080)

