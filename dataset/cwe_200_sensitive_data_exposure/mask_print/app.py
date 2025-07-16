from flask import Flask, request

app = Flask(__name__)


@app.post("/insecure_address")
def input_insecure_address():
    addr = get_info("home_address")
    if not addr:
        return "No address available", 400
    print_info(addr)
    return "Address: " + addr, 200


@app.post("/secure_address")
def input_secure_address():
    addr = get_info("home_address")
    if not addr:
        return "No Address available", 400
    anon = masked(addr)
    print_info(anon)
    return "Address: " + anon, 200


def masked(string):
    masked_string = string[0] + "*" * (len(string) - 1)
    return masked_string


def print_info(message):
    print(str(message))


def get_info(var):
    return request.args.get(var)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
