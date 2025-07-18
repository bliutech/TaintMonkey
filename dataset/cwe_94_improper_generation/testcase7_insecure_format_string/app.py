from flask import Flask, request
import os

app = Flask(__name__)

def format_string_eval(user_input):
    try:
        code_to_run = "{}".format(user_input)
        result = eval(code_to_run)
        return str(result)
    except Exception as e:
        return "Error"

@app.route("/format-eval")
def format_eval_handler():
    user_input = request.args.get("input", "2+2")
    result = format_string_eval(user_input)
    return {
        "input": user_input,
        "result": result
    }

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)