from flask import Flask, request, jsonify, render_template
from key_manager import KeyManager

app = Flask(__name__)
app.static_folder = 'static'
key_manager = KeyManager()


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encr_api", methods=["POST"])
def encrypt():
    print(request.json)
    return request.json

@app.route("/list_keys", methods=["GET"])
def list_keys():
	return jsonify(key_manager.list_keys())	

@app.route("/generate_key_pair", methods=["POST"])
def generate_key_pair():
     key_manager.generate_key_pair(request.json["name"], request.json["email"], request.json["password"], request.json["key_size"])
     return jsonify({"status": "success"})	
	


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")