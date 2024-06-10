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
	

@app.route('/access_private_key', methods=['POST'])
def access_private_key():
    data = request.json
    key_id = data.get('key_id')
    password = data.get('password')
    
    private_key_info = key_manager.get_private_key_by_id(key_id)
    if private_key_info:
        return jsonify(private_key_info), 200
    else:
        return jsonify({"message": "Access denied. Incorrect password or key not found."}), 403

@app.route('/remove_key', methods=['DELETE'])
def remove_key():
    data = request.json
    key_id = data.get('key_id')
    
    key_manager.remove_key(key_id)
    return jsonify({"message": f"Removed key with ID: {key_id}"}), 200

@app.route('/get_public_key_by_id/<int:key_id>', methods=['GET'])
def get_public_key_by_id(key_id):
    public_key_info = key_manager.get_public_key_by_id(key_id)
    if public_key_info:
        return jsonify(public_key_info), 200
    else:
        return jsonify({"message": "Public key not found."}), 404

@app.route('/get_private_key_by_id/<int:key_id>', methods=['POST'])
def get_private_key_by_id(key_id):
    password = request.json.get('password')
    private_key_info = key_manager.get_private_key_by_id(key_id, password)
    if private_key_info:
        return jsonify(private_key_info), 200
    else:
        return jsonify({"message": "Private key not found or access denied."}), 403

@app.route('/get_public_keys_by_user_id/<user_id>', methods=['GET'])
def get_public_keys_by_user_id(user_id):
    public_keys_info = key_manager.get_public_keys_by_user_id(user_id)
    return jsonify(public_keys_info), 200

@app.route('/get_private_keys_by_user_id/<user_id>', methods=['POST'])
def get_private_keys_by_user_id(user_id):
    password = request.json.get('password')
    private_keys_info = key_manager.get_private_keys_by_user_id(user_id, password)
    if private_keys_info:
        return jsonify(private_keys_info), 200
    else:
        return jsonify({"message": "Private key not found or access denied."}), 403

@app.route('/import_key', methods=['POST'])
def import_key():
    data = request.json
    filepath = data.get('filepath')
    user_id = data.get('user_id')
    key_passwd = data.get('password')

    result = key_manager.import_key(filepath, user_id, key_passwd)
    if result['message'] == "Key imported successfully.":
        return jsonify(result), 201
    else:
        return jsonify(result), 400

@app.route('/export_public_key/<int:key_id>', methods=['POST'])
def export_public_key(key_id):
    data = request.json
    filepath = data.get('filepath')

    success= key_manager.export_public_key(key_id, filepath)
    if not success:
        return jsonify({"message": "Key not found."}), 404
    return jsonify({"message": "Public key exported successfully."}), 200

@app.route('/export_private_key/<int:key_id>', methods=['POST'])
def export_private_key(key_id):
    data = request.json
    filepath = data.get('filepath')
    key_passwd = data.get('password')

    success = key_manager.export_private_key(key_id, filepath, key_passwd)
    print(success)
    if not success:
        return jsonify({"message": "Access denied. Incorrect password or key not found."}), 403
    return jsonify({"message": "Private key exported successfully."}), 200

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")