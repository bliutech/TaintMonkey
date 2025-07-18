from flask import Flask, request, jsonify
import math

app = Flask(__name__)

def safe_eval(expression):
    safe_globals = {"__builtins__": None}
    safe_locals = {
        "sqrt": math.sqrt,
        "pow": math.pow,
        "sin": math.sin,
        "cos": math.cos,
        "tan": math.tan,
        "log": math.log,
        "pi": math.pi,
        "e": math.e,
        "abs": abs,
        "max": max,
        "min": min,
    }

    try:
        result = eval(expression, safe_globals, safe_locals)
        return result
    except Exception as e:
        return "Error"

@app.route("/calculate", methods=['POST'])
def calculate_handler():
    data = request.get_json()
    expression = data.get("expr", "2+2") if data else "2+2"
    
    result = safe_eval(expression)
    
    return jsonify({
        "expression": expression,
        "result": result
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)