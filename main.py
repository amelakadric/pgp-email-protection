from flask import Flask, request, jsonify, render_template, Response, send_file
from key_manager import KeyManager
from PGPFacade import PGPFacade

app = Flask(__name__)
app.static_folder = 'static'
key_manager = KeyManager()


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encr_api", methods=["POST"])
def encrypt():
    try:
        aes_enc_msg = request.form["aes_enc_msg"]
        des3_enc_msg = request.form["des3_enc_msg"]
        private_key_id = int(request.form["private_key_id"])
        private_key_password = request.form["private_key_password"]
        public_key_id = int(request.form["public_key_id"])
        sign = request.form["sign"]
        compress = request.form["compress"]
        radix64 = request.form["radix64"]
        msg_data = None
        if request.form["text_or_file"] == "file":
            msg_data = request.files.get("file").stream.read()
        else: msg_data = request.form["text"].encode()
        options = []
        if aes_enc_msg == "true": options += ["aes_encrypt"]
        if des3_enc_msg == "true": options += ["3des_encrypt"]
        if private_key_id != "null": options += [private_key_id]
        options += [private_key_password]
        if public_key_id != "null": options += [public_key_id]
        if sign == "true": options += ["sign_msg"]
        if compress == "true": options += ["compression"]
        if radix64 == "true": options += ["radix64"]

        pgpf = PGPFacade(
            key_manager.get_private_key_store(),
            key_manager.get_public_key_store()
        )

        result = None
        if request.form["op_type"] == "encrypt_message":
            pgpf.set_send_msg_params(
                sender_prk_id=private_key_id,
                sender_prk_passwd=private_key_password,
                sender_puk_id=private_key_id,
                receiver_puk_id=public_key_id
            )
            result = pgpf.pgp_encrypt_message(data=msg_data, filename="user_request.pgp", options=options)
        elif request.form["op_type"] == "decrypt_message":
            result = pgpf.pgp_decrypt_message(data=msg_data, filename="user_request.pgp", passwd=private_key_password, options=options)
        print(result)
        return result

    except FileExistsError as e:
        return jsonify({
            "ERROR": e.args,
            "aes_enc_msg": request.form["aes_enc_msg"],
            "des3_enc_msg": request.form["des3_enc_msg"],
            "private_key_id": request.form["private_key_id"],
            "private_key_password": request.form["private_key_password"],
            "public_key_id": request.form["public_key_id"],
            "sign": request.form["sign"],
            "compress": request.form["compress"],
            "radix64": request.form["radix64"],
            "text_or_file": request.form["text_or_file"],
            "op_type": request.form["op_type"],
        })

@app.route("/download")
def download_file():
    return send_file("user_request.pgp")

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
    key_id = int(data.get('key_id'))

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

    private_key_info = key_manager.get_private_key_by_id(int(key_id), password)
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


@app.route('/import_key_pair', methods=['POST'])
def import_key_pair():
    file = request.files['file']
    user_id = request.form['user_id']
    name = request.form['name']
    password = request.form['password']
    file_content = file.read()

    result = key_manager.import_key(file_content, user_id, password, name)
    return jsonify(result), 201 if result['message'] == "Key pair imported successfully." else 400

    
@app.route('/import_public_key', methods=['POST'])
def import_public_key():
    if 'file' not in request.files:
        return jsonify({"message": "No file part in the request"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400

    user_id = request.form.get('user_id')
    name = request.form.get('name')

    if file:
        file_content = file.read().decode('utf-8')  # Read the file content

        result = key_manager.import_public_key(file_content, user_id, name)
        if result['message'] == "Key imported successfully.":
            return jsonify(result), 201
        else:
            return jsonify(result), 400
        
@app.route('/export_public_key', methods=['POST'])
def export_public_key():
    try:
        data = request.json
        key_id = int(data.get('key_id'))
        fileName = data.get('fileName')

        success = key_manager.export_public_key(key_id, f"./exports/{fileName}.pem")

        if success:
            return jsonify({"message": f"Public key '{key_id}' exported successfully to {fileName}.pem."}), 200
        else:
            return jsonify({"message": f"Failed to export public key '{key_id}'."}), 500

    except Exception as e:
        return jsonify({"message": f"Error exporting public key: {str(e)}"}), 500
    

@app.route('/export_key_pair/<int:key_id>', methods=['POST'])
def export_key_pair(key_id):
    data = request.json
    filename = data.get('filename')
    key_passwd = data.get('password')
    
    success = key_manager.export_private_key(int(key_id), f'./exports/{filename}.pem', key_passwd)
    if success:
        return jsonify({"message": "Key pair {key_id} exported successfully."}), 200
    else:
        return jsonify({"message": "Failed to export key pair."}), 400



if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")