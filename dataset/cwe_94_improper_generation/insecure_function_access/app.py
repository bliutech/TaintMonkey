from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/insecure", methods=["GET"])
def insecure_function():
    function_name = request.args.get("function", "")
    
    try:
        result = eval(function_name)
        return jsonify({"result": str(result)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    app.run(debug=True)
