from flask import Flask, request, jsonify

app = Flask(__name__)


def calculate_expression(expression):
    try:
        result = eval(expression)
        return result
    except Exception as e:
        return "Error"


@app.route("/calculate", methods=["POST"])
def calculate_handler():
    data = request.get_json()
    expression = data.get("expr", "2+2") if data else "2+2"

    result = calculate_expression(expression)

    return jsonify({"expression": expression, "result": result})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
