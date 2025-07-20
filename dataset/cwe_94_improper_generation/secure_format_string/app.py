from flask import Flask, request, jsonify
import string

app = Flask(__name__)


class SecureFormatter:
    ALLOWED_TYPES = {"s", "d", "f", "g", "x", "o", "e", "%"}
    ALLOWED_ALIGN = {"<", ">", "^"}
    ALLOWED_FORMAT_CHARS = (
        string.digits + ".-" + "".join(ALLOWED_TYPES) + "".join(ALLOWED_ALIGN)
    )

    def __init__(self):
        self.max_string_length = 1000
        self.max_format_specs = 10

    def validate_format_string(self, format_str):
        if not isinstance(format_str, str):
            raise ValueError("Invalid format string")

        if len(format_str) > self.max_string_length:
            raise ValueError("String too long")

        format_count = format_str.count("{") + format_str.count("}")
        if format_count > self.max_format_specs * 2:
            raise ValueError("Too many specifiers")

        if format_str.count("{") != format_str.count("}"):
            raise ValueError("Mismatched braces")

        if "{" in format_str and "}" in format_str:
            try:
                parsed = string.Formatter().parse(format_str)

                for literal_text, field_name, format_spec, conversion in parsed:
                    if field_name is not None:
                        if not field_name.isdigit():
                            raise ValueError("Only positional arguments allowed")

                    if format_spec:
                        if len(format_spec) > 10:
                            raise ValueError("Format specification too long")

                        if format_spec[0] in self.ALLOWED_ALIGN:
                            format_spec = format_spec[1:]

                        if any(
                            c not in string.digits + "." + "".join(self.ALLOWED_TYPES)
                            for c in format_spec
                        ):
                            raise ValueError("Invalid format specification")

                    if conversion and conversion not in self.ALLOWED_TYPES:
                        raise ValueError("Invalid conversion type")
            except Exception:
                raise ValueError("Invalid format string")

    def validate_value(self, value):
        if not isinstance(value, (str, int, float)):
            raise ValueError("Invalid value")

        if isinstance(value, str) and len(value) > self.max_string_length:
            raise ValueError("Value is too long")

        if isinstance(value, (int, float)) and abs(value) > 1e10:
            raise ValueError("Number is too large")

        return value

    def safe_format(self, format_str, *args):
        self.validate_format_string(format_str)

        safe_args = []
        for arg in args:
            safe_args.append(self.validate_value(arg))

        try:
            result = format_str.format(*safe_args)
            if len(result) > self.max_string_length:
                raise ValueError("Result is too long")
            return result
        except Exception:
            raise ValueError("Invalid format operation")


@app.route("/format", methods=["POST"])
def format_string():
    try:
        data = request.get_json()
        if not data or "template" not in data or "values" not in data:
            return jsonify(
                {"error": "Missing template or values", "status": "error"}
            ), 400

        template = data["template"]
        values = data["values"]

        if not isinstance(values, list):
            return jsonify({"error": "Values must be a list", "status": "error"}), 400

        formatter = SecureFormatter()
        result = formatter.safe_format(template, *values)

        return jsonify(
            {
                "template": template,
                "values": values,
                "result": result,
                "status": "success",
            }
        )

    except ValueError as e:
        return jsonify(
            {
                "template": template if "template" in locals() else None,
                "values": values if "values" in locals() else None,
                "error": str(e),
                "status": "error",
            }
        ), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
