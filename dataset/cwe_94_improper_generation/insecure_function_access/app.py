from flask import Flask, request, jsonify

app = Flask(__name__)


def insecure_function(function_name):
    result = eval(function_name)
    return result


@app.route("/insecure", methods=["GET"])
def insecure_function():
    function_name = request.args.get("function", "")

    try:
        result = insecure_function(function_name)
        return jsonify({"result": str(result)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    app.run(debug=True)
