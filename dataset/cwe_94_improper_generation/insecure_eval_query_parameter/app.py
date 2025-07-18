from flask import Flask, request, jsonify

app = Flask(__name__)


def calculate_expression(expression):
    try:
        result = eval(expression)
        return result
    except Exception as e:
        return f"Error"


@app.route("/calculate")
def calculate_handler():
    # query
    expression = request.args.get("expr", "2+2")

    # get results
    result = calculate_expression(expression)

    return jsonify({"expression": expression, "result": result})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
