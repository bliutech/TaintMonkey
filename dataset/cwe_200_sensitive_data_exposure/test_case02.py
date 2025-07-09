from flask import Flask, request
import hashlib

app = Flask(__name__)

@app.post("/insecure_register")
def register_insecure_name ():
    name = request.args.get("name")
    if name is None or "":
        return ("No name available", 400)
    else:
        app.logger.info(f"Name entered: {name}")
        return ("Name: " + name, 200)

@app.post("/secure_register")
def register_secure_name():
    name = request.args.get("name")
    if name is None or "":
        return ("No name available", 400)
    else:
        anon = hashlib.sha256(name.encode()).hexdigest()
        app.logger.info(f"Name entered: {anon}")
        return ("Name: " + anon, 200)


if (__name__ == "__main__"):
    app.run(host="0.0.0.0", port=5000)

