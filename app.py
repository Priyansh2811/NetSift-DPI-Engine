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
COMPILER = "g++" if IS_LINUX else "g++.exe"

# Safe memory buffer space for Linux/Windows structures
BASE_DIR = "/tmp" if IS_LINUX else os.getcwd()
BINARY_NAME = os.path.join(BASE_DIR, "dpi_engine" if IS_LINUX else "dpi_engine.exe")

CPP_SOURCES = [
    "src/dpi_mt.cpp",
    "src/packet_parser.cpp",
    "src/pcap_reader.cpp",
    "src/sni_extractor.cpp",
    "src/types.cpp"
]

def compile_core_engine():
    """Compiles the C++ engine sequentially into the designated target directory"""
    print("[Python Backend] Running sequential compilation flags...")
    if not os.path.exists("src"):
        return False, "'src' folder framework missing"

    compile_cmd = [COMPILER, "-std=c++17", "-pthread"] + CPP_SOURCES + ["-o", BINARY_NAME]
    
    try:
        result = subprocess.run(compile_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=45)
        if result.returncode == 0:
            return True, None
        return False, f"Compiler mismatch logs:\n{result.stderr}"
    except Exception as e:
        return False, str(e)

# --- API GATEWAY ENDPOINTS ---

@app.route('/', methods=['GET'])
def health_check():
    return jsonify({"status": "online", "platform": platform.system()}), 200

@app.route('/api/analyze', methods=['POST'])
def analyze_pcap():
    # Safe validation wrapper to prevent unhandled routing crashes
    if 'file' not in request.files:
        return jsonify({"error": "No file stream intercepted"}), 400
        
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({"error": "Null filename allocation"}), 400

    temp_pcap_path = os.path.join(BASE_DIR, "runtime_target.pcap")
    try:
        uploaded_file.save(temp_pcap_path)
    except Exception as save_err:
        return jsonify({"error": f"Storage system mapping error: {str(save_err)}"}), 500

    # Dynamic fallback check for binary maps
    if not os.path.exists(BINARY_NAME):
        success, compilation_error = compile_core_engine()
        if not success:
            if os.path.exists(temp_pcap_path): os.remove(temp_pcap_path)
            return jsonify({"error": "C++ Backend Engine Compilation Fault", "details": compilation_error}), 500

    if IS_LINUX and os.path.exists(BINARY_NAME):
        os.chmod(BINARY_NAME, 0o755)

    try:
        print("[Python Backend] Initiating C++ subprocess intercept...")
        engine_process = subprocess.run(
            [BINARY_NAME, temp_pcap_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30 # Prevent long thread freeze loops
        )

        if os.path.exists(temp_pcap_path):
            os.remove(temp_pcap_path)

        if engine_process.returncode != 0:
            # Captures standard out errors instead of killing server pipeline
            return jsonify({
                "error": "C++ Engine runtime failure or structural parsing mismatch",
                "details": engine_process.stderr or "Check if your C++ main loop output prints valid structural JSON strings."
            }), 500

        # Safe parsing wrap to ensure no malformed outputs breaks Flask
        try:
            structured_telemetry = json.loads(engine_process.stdout)
            return jsonify(structured_telemetry), 200
        except Exception as json_err:
            return jsonify({
                "error": "C++ Engine output structure is not a valid JSON schema matrix",
                "raw_output": engine_process.stdout
            }), 500

    except subprocess.TimeoutExpired:
        if os.path.exists(temp_pcap_path): os.remove(temp_pcap_path)
        return jsonify({"error": "Execution routine timeout. Package processing took too long"}), 504
    except Exception as e:
        if os.path.exists(temp_pcap_path): os.remove(temp_pcap_path)
        return jsonify({"error": f"Internal microservice fault: {str(e)}"}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)