import os
import platform
import subprocess
import json
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enables cross-origin requests for your Vercel frontend

# --- PLATFORM CONFIGURATIONS ---
IS_LINUX = platform.system() == "Linux"
COMPILER = "g++" if IS_LINUX else "g++.exe"
BINARY_NAME = "./dpi_engine" if IS_LINUX else "dpi_engine.exe"

# --- CORE FILES MAPPING ---
CPP_SOURCES = [
    "src/dpi_mt.cpp",
    "src/packet_parser.cpp",
    "src/pcap_reader.cpp",
    "src/sni_extractor.cpp",
    "src/types.cpp"
]
OUTPUT_FLAG = ["-o", "dpi_engine" if IS_LINUX else "dpi_engine.exe"]

def compile_core_engine():
    """Compiles the C++ engine sequentially on startup depending on runtime OS"""
    print(f"[Python Backend] Detected Platform: {platform.system()}")
    print("[Python Backend] Initializing verification and compilation of C++ Core Engine...")
    
    # Check if source directory exists
    if not os.path.exists("src"):
        print("[Python Backend] Error: 'src' directory not found!")
        return False

    # Compilation Command Framework
    compile_cmd = [COMPILER, "-std=c++17", "-pthread"] + CPP_SOURCES + OUTPUT_FLAG
    
    try:
        print(f"[Python Backend] Executing build command: {' '.join(compile_cmd)}")
        result = subprocess.run(compile_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode == 0:
            print("[Python Backend] Verification complete! C++ Core Engine compiled successfully.")
            return True
        else:
            print(f"[Python Backend] Compilation Failed!\nLog Output:\n{result.stderr}")
            return False
            
    except Exception as e:
        print(f"[Python Backend] Internal compiler process execution fault: {str(e)}")
        return False

# --- API GATEWAY ENDPOINTS ---

@app.route('/', methods=['GET'])
def health_check():
    return jsonify({
        "status": "online",
        "engine_architecture": "C++17 Multi-Threaded Data Pipeline",
        "platform_detected": platform.system()
    }), 200

@app.route('/api/analyze', methods=['POST'])
def analyze_pcap():
    """Handles PCAP uploads, passes them to compiled binary, and returns JSON telemetry"""
    if 'file' not in request.files:
        return jsonify({"error": "No file stream intercepted in payload metadata"}), 400
        
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({"error": "Null filename allocation detected"}), 400

    # Temporary storage mapping for the incoming stream
    temp_pcap_path = os.path.join(os.getcwd(), "runtime_target.pcap")
    uploaded_file.save(temp_pcap_path)

    # If binary is missing, force compile it right now!
    if not os.path.exists(BINARY_NAME):
        print("[Python Backend] Binary missing. Running dynamic runtime compilation...")
        if not compile_core_engine():
            if os.path.exists(temp_pcap_path):
                os.remove(temp_pcap_path)
            return jsonify({"error": "C++ Subprocess execution error: Compilation failed on cloud server"}), 500

    try:
        print(f"[Python Backend] Passing packet streams through {BINARY_NAME} core wrapper...")
        
        # Execute the compiled binary
        engine_process = subprocess.run(
            [BINARY_NAME, temp_pcap_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if os.path.exists(temp_pcap_path):
            os.remove(temp_pcap_path)

        if engine_process.returncode != 0:
            print(f"[Core Engine Error Log]: {engine_process.stderr}")
            return jsonify({"error": f"Binary engine execution failed: {engine_process.stderr}"}), 500

        raw_output_payload = engine_process.stdout
        structured_telemetry = json.loads(raw_output_payload)
        
        return jsonify(structured_telemetry), 200

    except Exception as e:
        if os.path.exists(temp_pcap_path):
            os.remove(temp_pcap_path)
        return jsonify({"error": f"Internal orchestration fault: {str(e)}"}), 500
# --- RUN ORCHESTRATION ---
# --- RUN ORCHESTRATION ---
if __name__ == '__main__':
    # Binding port to environment configurations for dynamic production handling
    port = int(os.environ.get("PORT", 5000))
    
    print(f"[Python Backend] Instantly launching Flask on port {port} to pass Render port check...")
    # 0.0.0.0 par bind pehle chalega taaki Render proxy pass ho jaye
    app.run(host='0.0.0.0', port=port, debug=False)

# ====================================================================
# FORCE BYPASS FOR PORT SCANNING PROXIES V3
# ====================================================================
# ====================================================================
# TRIGGERING RE-BUILD PROTOCOL V2 FOR RENDER PORT SCANNING PROXIES
# ====================================================================