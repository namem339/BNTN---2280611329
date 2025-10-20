import socket, concurrent.futures, time, itertools

COMMON_PORTS = [20,21,22,23,25,53,80,110,139,143,443,445,465,587,993,995,1433,1521,2049,2375,3306,3389,5432,5900,6379,8000,8080,8443]

def check_port(host:str, port:int, timeout:float=0.6):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, True
    except Exception:
        return port, False

def scan(host:str, ports=None, rate_limit:int=200, max_workers:int=200):
    ports = ports or COMMON_PORTS
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for chunk_start in range(0, len(ports), rate_limit):
            chunk = ports[chunk_start:chunk_start+rate_limit]
            futs = [ex.submit(check_port, host, p) for p in chunk]
            for fut in futs:
                p, ok = fut.result()
                if ok: open_ports.append(p)
            time.sleep(0.1)
    return sorted(open_ports)
