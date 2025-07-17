import os
from flask import Flask, request
import re

app = Flask(__name__)

def open_file_command(file):
    return f"cat {file}"

@app.get("/insecure")
def insecure_handler():
    file = request.args.get("file") or "example.txt"
    
    exit_code = os.system(open_file_command(file))
    
    # os.system = 0 means a success
    if exit_code == 0:
        return "Command executed successfully"
    else:
        return f"Command exit code failed", 500
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
