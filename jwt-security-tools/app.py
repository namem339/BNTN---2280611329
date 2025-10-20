from flask import Flask, render_template, request
from modules.port_scanner import scan
from modules.service_detector import detect
from modules.vuln_checker import check
from modules.network_mapper import scan_cidr
from modules.email_sender import send_email
import os, json
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

@app.route("/", methods=["GET","POST"])
def index():
    if request.method == "POST":
        target = request.form.get("target","").strip()
        ports  = request.form.get("ports","").strip()
        email  = request.form.get("email","").strip()
        result = {}
        if "/" in target:
            alive = scan_cidr(target)
            result = {"alive": alive}
        else:
            p = [int(x) for x in ports.split(",") if x] if ports else None
            open_ports = scan(target, ports=p)
            result = {"target": target, "open_ports": open_ports, "services":{}, "vulns":{}}
            for port in open_ports:
                fp = detect(target, port)
                result["services"][port] = fp
                vulns = check(fp) if isinstance(fp, str) else []
                if vulns: result["vulns"][port] = vulns
        if email:
            send_email(f"NetRecon report for {target}", json.dumps(result, indent=2), to_addr=email)
        return render_template("result.html", result=result)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
