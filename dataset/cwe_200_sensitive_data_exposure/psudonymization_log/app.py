from flask import Flask, request
from faker import Faker

app = Flask(__name__)


@app.post("/insecure_phone")
def register_insecure_phone():
    phone_num = get_info("phone_number")
    if not phone_num:
        return "Please enter a valid Phone Number", 400
    log_info(phone_num)
    return "Phone Number: " + phone_num, 200


@app.post("/secure_phone")
def register_secure_phone():
    phone_num = get_info("phone_number")
    if not phone_num:
        return "Please enter a valid Phone Number", 400
    anon = psudo(phone_num)
    log_info(anon)
    return "Phone Number: " + anon, 200


def psudo(phone_num):
    fake = Faker()
    return fake.phone_number()


def log_info(message):
    app.logger.info(message)


def get_info(var):
    return request.args.get(var)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
