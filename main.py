from flask import Flask, request, jsonify, render_template

app = Flask(__name__)
app.static_folder = 'static'

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encr_api", methods=["POST"])
def encrypt():
    print(request.json)
    return request.json

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")