# Very small demo ruleset. In real life, use an authenticated scanner or advisories database.
RULES = [
    ("OpenSSH_7.2", "CVE-2016-0777/8 (roaming) - upgrade"),
    ("OpenSSL/1.0.1", "CVE-2014-0160 Heartbleed - upgrade"),
    ("vsftpd 2.3.4", "Backdoor in 2.3.4 - avoid"),
]

def check(service_fingerprint:str):
    hits = []
    for needle, advisory in RULES:
        if needle.lower() in service_fingerprint.lower():
            hits.append(advisory)
    return hits
