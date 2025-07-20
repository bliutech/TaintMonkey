from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/secure", methods=["GET"])
def secure_function():
    function_name = request.args.get("function", "")
    arg = request.args.get("arg", "")

    allowed_functions = {
        "len": len,
        "abs": abs,
        "sum": lambda x: sum([int(i) for i in x.split(",")]) if x else 0,
        "min": lambda x: min([int(i) for i in x.split(",")]) if x else 0,
        "max": lambda x: max([int(i) for i in x.split(",")]) if x else 0,
        "round": lambda x: round(float(x)) if x else 0,
    }

    if function_name not in allowed_functions:
        return jsonify({"error": "Function not allowed"}), 403

    try:
        if function_name == "abs":
            result = allowed_functions[function_name](int(arg))
        else:
            result = allowed_functions[function_name](arg)
        return jsonify({"result": str(result)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    app.run(debug=True)
