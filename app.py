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

# Safe temporary storage environment paths for Linux/Windows
BASE_DIR = "/tmp" if IS_LINUX else os.getcwd()
BINARY_NAME = os.path.join(BASE_DIR, "dpi_engine" if IS_LINUX else "dpi_engine.exe")

# --- CORE FILES MAPPING ---
CPP_SOURCES = [
    "src/dpi_mt.cpp",
    "src/packet_parser.cpp",
    "src/pcap_reader.cpp",
    "src/sni_extractor.cpp",
    "src/types.cpp"
]

def compile_core_engine():
    """Compiles the C++ engine sequentially into the designated target directory"""
    print(f"[Python Backend] Initializing verification and compilation of C++ Core Engine...")
    
    if not os.path.exists("src"):
        print("[Python Backend] Error: 'src' directory not found!")
        return False, "'src' directory missing from repository context"

    # Command compilation setup
    compile_cmd = [COMPILER, "-std=c++17", "-pthread"] + CPP_SOURCES + ["-o", BINARY_NAME]
    
    try:
        print(f"[Python Backend] Executing build command: {' '.join(compile_cmd)}")
        result = subprocess.run(compile_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode == 0:
            print(f"[Python Backend] Verification complete! C++ Engine compiled at {BINARY_NAME}")
            return True, None
        else:
            error_log = f"Stdout: {result.stdout}\nStderr: {result.stderr}"
            print(f"[Python Backend] Compilation Failed!\nLog Output:\n{error_log}")
            return False, error_log
            
    except Exception as e:
        return False, str(e)

# --- API GATEWAY ENDPOINTS ---

@app.route('/', methods=['GET'])
def health_check():
    return jsonify({
        "status": "online",
        "platform_detected": platform.system(),
        "binary_target_path": BINARY_NAME
    }), 200

@app.route('/api/analyze', methods=['POST'])
def analyze_pcap():
    if 'file' not in request.files:
        return jsonify({"error": "No file stream intercepted in payload metadata"}), 400
        
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({"error": "Null filename allocation detected"}), 400

    # Storing inside isolated absolute safe runtime directories
    temp_pcap_path = os.path.join(BASE_DIR, "runtime_target.pcap")
    uploaded_file.save(temp_pcap_path)

    # Dynamic run-time compiler invocation check
    if not os.path.exists(BINARY_NAME):
        success, compilation_error = compile_core_engine()
        if not success:
            if os.path.exists(temp_pcap_path):
                os.remove(temp_pcap_path)
            # CRITICAL: Yeh error ab direct frontend par exact pipeline compilation trace phenkegi!
            return jsonify({
                "error": "C++ Compilation Fault on Server Node",
                "details": compilation_error
            }), 500

    # Ensure execution access privileges on Linux instance
    if IS_LINUX and os.path.exists(BINARY_NAME):
        os.chmod(BINARY_NAME, 0o755)

    try:
        print(f"[Python Backend] Passing packet streams through sub-process layers...")
        engine_process = subprocess.run(
            [BINARY_NAME, temp_pcap_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if os.path.exists(temp_pcap_path):
            os.remove(temp_pcap_path)

        if engine_process.returncode != 0:
            return jsonify({
                "error": "Binary executable runtime segmentation fault",
                "details": engine_process.stderr
            }), 500

        return jsonify(json.loads(engine_process.stdout)), 200

    except Exception as e:
        if os.path.exists(temp_pcap_path):
            os.remove(temp_pcap_path)
        return jsonify({"error": f"Internal orchestration fault: {str(e)}"}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)