import argparse, json
from modules.port_scanner import scan
from modules.service_detector import detect
from modules.vuln_checker import check
from modules.network_mapper import scan_cidr

def main():
    ap = argparse.ArgumentParser(description="NetRecon (educational). Scan only hosts you own or have permission for.")
    ap.add_argument("target", help="host or CIDR (e.g., 192.168.1.0/24)")
    ap.add_argument("--ports", help="comma-separated ports", default="")
    args = ap.parse_args()
    t = args.target
    if "/" in t:
        alive = scan_cidr(t)
        print(json.dumps({"alive": alive}, indent=2))
        return
    ports = [int(p) for p in args.ports.split(",") if p] if args.ports else None
    open_ports = scan(t, ports=ports)
    result = {"target": t, "open_ports": open_ports, "services":{}, "vulns":{}}
    for p in open_ports:
        fp = detect(t, p)
        result["services"][p] = fp
        vulns = check(fp) if isinstance(fp, str) else []
        if vulns: result["vulns"][p] = vulns
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
