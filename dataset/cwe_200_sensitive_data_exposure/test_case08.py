from flask import Flask, request
import secrets

app = Flask(__name__)

@app.post("/insecure_bank")
def input_insecure_bank ():
    bank_num = request.args.get("bank_number")
    if not bank_num:
        return "No bank number available", 400
    print ("Bank Number entered: "+ bank_num)
    return "Bank Number: " + bank_num, 200

@app.post("/secure_bank")
def input_secure_bank():
    bank_num = request.args.get("bank_number")
    if not bank_num:
        return "No bank number available", 400
    anon = tokenize(bank_num)
    print ("Bank Number entered: "+ bank_num)
    return "Bank Number: " + anon, 200

def tokenize(string):
    token = secrets.token_hex(64)
    return token

if __name__ == "__main__":
    app.run (host="0.0.0.0", port=5000)

