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

@app.route('/generate_key_pair', methods=['POST'])
def generate_key_pair():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    key_size = int(data.get('key_size', 2048))

    key_manager.generate_key_pair(name, email, password, key_size)
    return jsonify({"message": f"Generated {key_size}-bit key pair for {name} ({email})."}), 201

@app.route('/list_private_key_ring', methods=['GET'])
def list_private_key_ring():
    keys = key_manager.list_private_key_ring()
    return jsonify(keys), 200

@app.route('/list_public_key_ring', methods=['GET'])
def list_public_key_ring():
    keys = key_manager.list_public_key_ring()
    return jsonify(keys), 200

@app.route('/access_private_key', methods=['POST'])
def access_private_key():
    data = request.json
    key_id = data.get('key_id')
    password = data.get('password')

    private_key_info = key_manager.get_private_key_by_id(key_id, password)
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
    data = request.json
    password = data.get('password')

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
    data = request.json
    password = data.get('password')

    private_keys_info = key_manager.get_private_keys_by_user_id(user_id, password)
    if private_keys_info:
        return jsonify(private_keys_info), 200
    else:
        return jsonify({"message": "Access denied or no keys found for the user ID."}), 403

@app.route('/get_public_key_by_name/<name>', methods=['GET'])
def get_public_key_by_name(name):
    public_key_info = key_manager.get_public_key_by_name(name)
    if public_key_info:
        return jsonify(public_key_info), 200
    else:
        return jsonify({"message": "Public key not found."}), 404

@app.route('/get_private_key_by_name/<name>', methods=['POST'])
def get_private_key_by_name(name):
    data = request.json
    password = data.get('password')

    private_key_info = key_manager.get_private_key_by_name(name, password)
    if private_key_info:
        return jsonify(private_key_info), 200
    else:
        return jsonify({"message": "Private key not found or access denied."}), 403


@app.route('/import_key', methods=['POST'])
def import_key():
    data = request.json
    filepath = data.get('filepath')
    user_id = data.get('user_id')
    key_passwd = data.get('password')
    name = data.get('name')

    result = key_manager.import_key(filepath, user_id, key_passwd, name)
    if result['message'] == "Key imported successfully.":
        return jsonify(result), 201
    else:
        return jsonify(result), 400
    
@app.route('/import_public_key', methods=['POST'])
def import_public_key():
    data = request.json
    filepath = data.get('filepath')
    user_id = data.get('user_id')
    name = data.get('name')

    result = key_manager.import_public_key(filepath, user_id, name)
    if result['message'] == "Key imported successfully.":
        return jsonify(result), 201
    else:
        return jsonify(result), 400

@app.route('/export_public_key/<int:key_id>', methods=['POST'])
def export_public_key(key_id):
    data = request.json
    filepath = data.get('filepath')

    success = key_manager.export_public_key(key_id, filepath)
    if success:
        return jsonify({"message": "Public key exported successfully."}), 200
    else:
        return jsonify({"message": "Failed to export public key."}), 400

@app.route('/export_private_key/<int:key_id>', methods=['POST'])
def export_private_key(key_id):
    data = request.json
    filepath = data.get('filepath')
    key_passwd = data.get('password')

    success = key_manager.export_private_key(key_id, filepath, key_passwd)
    if success:
        return jsonify({"message": "Private key exported successfully."}), 200
    else:
        return jsonify({"message": "Failed to export private key."}), 400

@app.route('/export_key_pair/<int:key_id>', methods=['POST'])
def export_key_pair(key_id):
    data = request.json
    filepath = data.get('filepath')
    key_passwd = data.get('password')

    result = key_manager.export_key_pair(key_id, filepath, key_passwd)
    return jsonify(result), 200 if result['message'] == "Key pair exported successfully." else 400

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")