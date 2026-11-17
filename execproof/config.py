from __future__ import annotations

import re
from urllib.parse import urlparse

BLOCKED_COMMAND_TOKENS = re.compile(
    r"(^|[\s;&|])(rm\s|dd\s|mkfs|shutdown|reboot|halt|init\s|wget\s|curl\s|nc\s|ncat|"
    r"chmod\s|chown\s|kill\s|killall|useradd|passwd\s|crontab|>\s?/|>>|</dev/|fdisk|"
    r"/etc/shadow|/etc/passwd|history|nmap|python\s+-c|perl\s+-e)",
    re.IGNORECASE,
)


def is_safe_command(cmd: str) -> bool:
    return not BLOCKED_COMMAND_TOKENS.search(cmd)


def enforce_scope(url: str, scope_regex: str | None) -> bool:
    if not scope_regex:
        return True
    try:
        return re.search(scope_regex, urlparse(url).netloc) is not None
    except re.error:
        return False
