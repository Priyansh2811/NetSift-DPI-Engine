import os
import platform
import subprocess
import json
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# --- PLATFORM CONFIGURATIONS ---
IS_LINUX = platform.system() == "Linux"
# Render par binary seedhe root directory mein milegi jo humne build step mein banayi hai
BINARY_NAME = "./dpi_engine" if IS_LINUX else "dpi_engine.exe"

@app.route('/', methods=['GET'])
def health_check():
    return jsonify({
        "status": "online",
        "binary_found": os.path.exists(BINARY_NAME),
        "platform": platform.system()
    }), 200

@app.route('/api/analyze', methods=['POST'])
def analyze_pcap():
    if 'file' not in request.files:
        return jsonify({"error": "No file stream intercepted"}), 400
        
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({"error": "Null filename allocation"}), 400

    # Save incoming PCAP in current working directory
    temp_pcap_path = os.path.join(os.getcwd(), "runtime_target.pcap")
    try:
        uploaded_file.save(temp_pcap_path)
    except Exception as save_err:
        return jsonify({"error": f"Storage system mapping error: {str(save_err)}"}), 500

    # Verify if the pre-compiled binary exists
    if not os.path.exists(BINARY_NAME):
        if os.path.exists(temp_pcap_path): os.remove(temp_pcap_path)
        return jsonify({
            "error": "C++ Core Engine Binary Missing",
            "details": "The binary was not generated during Render's build step. Check build logs."
        }), 500

    try:
        print("[Python Backend] Executing pre-compiled C++ subprocess core...")
        engine_process = subprocess.run(
            [BINARY_NAME, temp_pcap_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30
        )

        # Cleanup the file immediately
        if os.path.exists(temp_pcap_path):
            os.remove(temp_pcap_path)

        if engine_process.returncode != 0:
            return jsonify({
                "error": "C++ Engine runtime failure",
                "details": engine_process.stderr or "Check code architecture mismatch."
            }), 500

        # Parse and return JSON
        try:
            structured_telemetry = json.loads(engine_process.stdout)
            return jsonify(structured_telemetry), 200
        except Exception as json_err:
            return jsonify({
                "error": "Malformed JSON output from C++ engine",
                "raw_output": engine_process.stdout
            }), 500

    except subprocess.TimeoutExpired:
        if os.path.exists(temp_pcap_path): os.remove(temp_pcap_path)
        return jsonify({"error": "Execution routine timeout"}), 504
    except Exception as e:
        if os.path.exists(temp_pcap_path): os.remove(temp_pcap_path)
        return jsonify({"error": f"Internal microservice fault: {str(e)}"}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)