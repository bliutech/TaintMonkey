from flask import Flask, request
import hashlib

app = Flask(__name__)


@app.post("/insecure_birthdate")
def input_insecure_birthdate():
    birth = get_info("birthdate")
    if not birth:
        return "No birthday available", 400
    elif len(birth) > 0 and len(birth) != 10:
        return "Please enter a valid date in the format MM-DD-YYYY", 400

    log_info(birth)
    return "Birthday: " + birth, 200


@app.post("/secure_birthdate")
def input_secure_birthdate():
    birth = get_info("birthdate")
    if not birth:
        return "No birthday available", 400
    elif len(birth) > 0 and len(birth) != 10:
        return "Please enter a valid date in the format MM-DD-YYYY", 400

    anon = generalize(birth)
    log_info(anon)
    return "Birthday: " + anon, 200


def generalize(string):
    years = string[-4:-1] + "0s"
    return years


def log_info(message):
    app.logger.info(message)


def get_info(var):
    return request.args.get(var)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
