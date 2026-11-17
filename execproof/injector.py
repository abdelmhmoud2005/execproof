from __future__ import annotations

import json
import urllib.parse


def build_request(cfg_url: str, cfg_data: str | None, point: dict, raw_payload: str,
                  url_encode: bool = True) -> tuple[str, str | None]:
    if point["kind"] == "query":
        return _inject_query(cfg_url, point, raw_payload, url_encode), None
    if point["kind"] == "json":
        return cfg_url, _inject_json(cfg_data, point, raw_payload)
    if point["kind"] == "body":
        return cfg_url, _inject_form(cfg_data, point, raw_payload, url_encode)
    return cfg_url, cfg_data


def _inject_query(cfg_url: str, point: dict, raw_payload: str, url_encode: bool) -> str:
    parsed = urllib.parse.urlparse(cfg_url)
    qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new_qs = [(k, raw_payload if (k == point["name"] and v == point["original"]) else v) for k, v in qs]
    if url_encode:
        query = urllib.parse.urlencode(new_qs)
    else:
        query = "&".join(f"{k}={v}" for k, v in new_qs)
    return urllib.parse.urlunparse(parsed._replace(query=query))


def _inject_form(cfg_data: str | None, point: dict, raw_payload: str, url_encode: bool) -> str:
    enc = urllib.parse.quote(raw_payload, safe="") if url_encode else raw_payload
    pairs = []
    if cfg_data:
        for part in cfg_data.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                if k == point["name"] and urllib.parse.unquote_plus(v) == point["original"]:
                    v = enc
                pairs.append((k, v))
            elif part:
                pairs.append((part, enc if part == point["name"] else ""))
    else:
        pairs = [(point["name"], enc)]
    return "&".join(f"{k}={v}" for k, v in pairs)


def _inject_json(cfg_data: str | None, point: dict, raw_payload: str) -> str | None:
    try:
        obj = json.loads(cfg_data or "{}")
    except (ValueError, TypeError):
        return cfg_data
    if isinstance(obj, dict) and point["name"] in obj:
        obj[point["name"]] = raw_payload
        return json.dumps(obj)
    return cfg_data
