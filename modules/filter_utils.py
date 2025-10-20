def allowed_target(host:str, whitelist=None, blacklist=None) -> bool:
    if whitelist:
        return host in whitelist
    if blacklist and host in blacklist:
        return False
    return True
