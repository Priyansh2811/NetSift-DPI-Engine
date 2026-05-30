import os
import platform
import subprocess
import json
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Render par binary isi naam se root par generate hogi
BINARY_NAME = "./dpi_engine" if platform.system() == "Linux" else "dpi_engine.exe"

@app.route('/', methods=['GET'])
def health_check():
    return jsonify({
        "status": "online",
        "binary_exists": os.path.exists(BINARY_NAME),
        "platform": platform.system()
    }), 200

@app.route('/api/analyze', methods=['POST'])
def analyze_pcap():
    if 'file' not in request.files:
        return jsonify({"error": "No file stream intercepted"}), 400
        
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({"error": "Null filename allocation"}), 400

    temp_pcap_path = os.path.join(os.getcwd(), "runtime_target.pcap")
    try:
        uploaded_file.save(temp_pcap_path)
    except Exception as save_err:
        return jsonify({"error": f"Storage mapping error: {str(save_err)}"}), 500

    if not os.path.exists(BINARY_NAME):
        if os.path.exists(temp_pcap_path): os.remove(temp_pcap_path)
        return jsonify({"error": "C++ Engine Core Binary Missing from Server"}), 500

    try:
        engine_process = subprocess.run(
            [BINARY_NAME, temp_pcap_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30
        )

        if os.path.exists(temp_pcap_path):
            os.remove(temp_pcap_path)

        if engine_process.returncode != 0:
            return jsonify({
                "error": "C++ Engine runtime failure",
                "details": engine_process.stderr
            }), 500

        return jsonify(json.loads(engine_process.stdout)), 200

    except Exception as e:
        if os.path.exists(temp_pcap_path): os.remove(temp_pcap_path)
        return jsonify({"error": f"Internal orchestration fault: {str(e)}"}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)