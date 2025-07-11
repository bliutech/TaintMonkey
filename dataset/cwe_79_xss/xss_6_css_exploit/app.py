from flask import Flask, request
import bleach

app = Flask(__name__)

@app.route("/style_insecure")
def style_insecure():
    color = request.args.get("color", "black")
    return f'''
        <html>
            <head>
                <style>
                    h1 {{ color: {color}; }}
                 </style>
            </head>
            <body>
                <h1>GSET 2025</h1>
                <p>The color is: {color}</p>
            </body>
        </html>
    '''

@app.route("/style_secure")
def style_secure():
    color = request.args.get("color", "black")
    upd_color = bleach.clean(color)
    return f'''
        <html>
            <head>
                 <style> 
                    h1 {{ color: {upd_color}; }} 
                 </style>
            </head>
            <body>
                <h1>GSET 2025</h1>
                <p>The color is: {upd_color}</p>
            </body>
        </html>
    '''

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)