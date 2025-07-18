from flask import Flask, request
import ast

app = Flask(__name__)


def secure_format_eval(user_input):
    try:
        result = ast.literal_eval(user_input)

        if not isinstance(result, (int, float)):
            return "Error: Only numeric results allowed"

        return "Result: {0}".format(result)

    except Exception as e:
        return "Error: Invalid expression"


@app.route("/format-eval")
def format_eval_handler():
    user_input = request.args.get("input", "2+2")
    result = secure_format_eval(user_input)

    return {"input": user_input, "result": result}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
