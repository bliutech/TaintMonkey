from flask import Flask, request, jsonify
import ast

app = Flask(__name__)


def secure_double_eval(expression):
    try:
        single_result = ast.literal_eval(expression)
        if not isinstance(single_result, str):
            return "Error, first result must be string"

        second_result = ast.literal_eval(single_result)
        return second_result
    except Exception as e:
        return "Error"


@app.route("/double-calculate")
def double_eval():
    expression = request.args.get("expr", "'2+2'")

    result = secure_double_eval(expression)

    return jsonify({"expression": expression, "result": result})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
