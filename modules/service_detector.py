from .banner_grabber import grab_banner

KNOWN = {
    22: "ssh",
    80: "http",
    443: "https",
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    3389: "rdp",
}

def detect(host:str, port:int) -> str:
    banner = grab_banner(host, port)
    if banner:
        return banner
    return KNOWN.get(port, "unknown")
