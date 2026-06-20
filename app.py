from flask import Flask, render_template, request, jsonify
import socket

app = Flask(__name__)

# This function checks if ports are open
def scan_ports(ip):
    ports = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS"}
    results = []
    risk_score = 0

    for port, service in ports.items():
        # Create a socket connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5) # Fast scan
        if s.connect_ex((ip, port)) == 0: # 0 means the port is OPEN
            severity = "HIGH" if port in [21, 80] else "MEDIUM"
            results.append({"port": port, "service": service, "severity": severity})
            risk_score += 10
        s.close()
    
    risk_level = "LOW" if risk_score == 0 else ("MEDIUM" if risk_score < 20 else "HIGH")
    return results, risk_level

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.json.get('target')
    try:
        ip = socket.gethostbyname(target) # Turn domain into IP
        found_ports, risk = scan_ports(ip)
        return jsonify({"status": "success", "ip": ip, "ports": found_ports, "risk": risk})
    except:
        return jsonify({"status": "error", "message": "Invalid Target"})

if __name__ == '__main__':
    app.run(debug=True)