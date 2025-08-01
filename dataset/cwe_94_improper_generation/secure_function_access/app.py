from flask import Flask, request, jsonify

app = Flask(__name__)

def execute_secure(function_name, arg):
    allowed_functions = {
        "len": len,
        "abs": abs,
        "sum": lambda x: sum([int(i) for i in x.split(",")]) if x else 0,
        "min": lambda x: min([int(i) for i in x.split(",")]) if x else 0,
        "max": lambda x: max([int(i) for i in x.split(",")]) if x else 0,
        "round": lambda x: round(float(x)) if x else 0,
    }

    if function_name not in allowed_functions:
        return None, "Function not allowed", 403

    try:
        if function_name == "abs":
            result = allowed_functions[function_name](int(arg))
        else:
            result = allowed_functions[function_name](arg)
        return result, None, None
    except Exception as e:
        return None, str(e), 400


@app.route("/secure", methods=["GET"])
def secure_function():
    function_name = request.args.get("function", "")
    arg = request.args.get("arg", "")

    result, error, status_code = execute_secure_function(function_name, arg)
    
    if error:
        return jsonify({"error": error}), status_code
    else:
        return jsonify({"result": str(result)})


if __name__ == "__main__":
    app.run(debug=True)
