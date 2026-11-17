import urllib.parse


def parse_raw_request(text: str, base_url: str = "") -> dict:
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or " " not in lines[0]:
        raise ValueError("raw request must start with 'METHOD /path HTTP/x'")
    method, target, _ = lines[0].split(" ", 2)
    headers = {}
    body_start = 0
    for i, line in enumerate(lines[1:], 1):
        if line.strip() == "":
            body_start = i + 1
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    body = "\n".join(lines[body_start:]).strip()
    if target.startswith("http://") or target.startswith("https://"):
        path = target
        base = ""
    else:
        path = target
        base = base_url.rstrip("/")
    url = base + path if base else path
    if not urllib.parse.urlparse(url).netloc:
        raise ValueError("no host found: pass -u with scheme://host as base")
    return {
        "method": method.upper(),
        "url": url,
        "headers": headers,
        "data": body or None,
    }
