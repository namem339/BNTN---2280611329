import ipaddress, concurrent.futures, socket, time

def host_up(host:str, timeout:float=0.5) -> bool:
    try:
        with socket.create_connection((host, 80), timeout=timeout):
            return True
    except Exception:
        return False

def scan_cidr(cidr:str, max_workers:int=100):
    net = ipaddress.ip_network(cidr, strict=False)
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(host_up, str(ip)): str(ip) for ip in net.hosts()}
        for f, ip in [(f, ip) for f, ip in futs.items()]:
            try:
                if f.result():
                    alive.append(ip)
            except Exception:
                pass
    return alive
