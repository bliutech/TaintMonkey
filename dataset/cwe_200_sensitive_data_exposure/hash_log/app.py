from flask import Flask, request
import hashlib

app = Flask(__name__)

@app.post("/insecure_register")
def register_insecure_ssnum ():
    ssnum = get_info("ssnum")
    if not ssnum:
        return "Please enter a valid SSN", 400
    log_info(ssnum)
    return "SS Number: " + ssnum, 200

@app.post("/secure_register")
def register_secure_ssnum():
    ssnum = get_info("ssnum")
    if not ssnum:
        return "Please enter a valid SSN", 400
    anon = hash_ssn(ssnum)
    log_info(anon)
    return "SS Number: " + anon, 200

def hash_ssn(ssnum):
    hashed= hashlib.sha256(ssnum.encode()).hexdigest()
    return hashed

def log_info (message):
    app.logger.info(message)

def get_info (var):
    return request.args.get(var)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

