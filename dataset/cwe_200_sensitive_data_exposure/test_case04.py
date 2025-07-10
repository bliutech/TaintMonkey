from flask import Flask, request
import hashlib

app = Flask(__name__)

@app.post("/insecure_address")
def input_insecure_address ():
    addr = request.args.get("home_address")
    if not addr:
        return "No address available", 400
    print ("Address entered: "+ addr)
    return "Address: " + addr, 200

@app.post("/secure_address")
def input_secure_address():
    addr = request.args.get("home_address")
    if not addr:
        return "No Address available", 400
    anon = masked(addr)
    print ("Address entered: "+ anon)
    return "Address: " + anon, 200

def masked(string):
    masked_string = string[0] + "*" * (len(string) - 1)
    return masked_string

if __name__ == "__main__":
    app.run (host="0.0.0.0", port=5000)

