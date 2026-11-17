import argparse
import sys

from . import __version__
from .models import ScanConfig
from .scanner import Scanner, ScanError
from .report import to_json, to_markdown, to_sarif


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="execproof",
        description="Professional CLI scanner for OS command injection / RCE. "
                    "DAST (echo/time/OOB/SSTI) + SAST source analysis. Safe-by-design.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a target URL (DAST) and/or source tree (SAST)")
    s.add_argument("-u", "--url", help="target URL including query string (required for dast/both)")
    s.add_argument("-X", "--method", default="GET", help="HTTP method (default GET)")
    s.add_argument("-d", "--data", help="request body (form or JSON)")
    s.add_argument("-H", "--header", action="append", default=[], help="extra header 'Name: Value' (repeatable)")
    s.add_argument("--raw", help="raw HTTP request file; -u provides scheme://host base")
    s.add_argument("--mode", choices=["dast", "sast", "both"], default="dast",
                   help="dast = dynamic only, sast = source only, both = merge (default dast)")
    s.add_argument("--src", help="source tree root for SAST mode")
    s.add_argument("--timeout", type=float, default=15.0, help="per-request timeout seconds")
    s.add_argument("--rate", type=float, default=5.0, help="max requests per second")
    s.add_argument("--threads", type=int, default=1, help="concurrent workers for injection points")
    s.add_argument("--time-delay", type=int, default=6, help="sleep delay used in time detector")
    s.add_argument("--time-threshold", type=float, default=4.0, help="minimum delta to count as delay")
    s.add_argument("--confirmations", type=int, default=2, help="repeats to confirm time-based hits")
    s.add_argument("--oob-domain", help="your OOB/collaborator domain (e.g. abc123.oast.fun)")
    s.add_argument("--oob-poll-url", help="HTTP endpoint returning recent OOB hits; enables auto-confirmation")
    s.add_argument("--scope-regex", help="regex limiting scans to matching hostnames")
    s.add_argument("--os", dest="os_type", choices=["unix", "windows"], default="unix",
                   help="target OS for impact payloads")
    s.add_argument("--no-impact", action="store_true", help="disable the impact-verification stage")
    s.add_argument("--detectors", default="echo,time,oob,ssti", help="comma list: echo,time,oob,ssti")
    s.add_argument("-o", "--output", help="write report to file (.json/.md/.sarif by extension)")
    s.add_argument("--format", choices=["json", "md", "sarif"], default="json", help="stdout format")

    sub.add_parser("version", help="print version")
    return p


def parse_headers(header_args):
    headers = {}
    for h in header_args:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "version":
        print(__version__)
        return 0

    cfg = ScanConfig(
        url=args.url or "",
        method=args.method,
        headers=parse_headers(args.header),
        data=args.data,
        timeout=args.timeout,
        rate=args.rate,
        threads=args.threads,
        time_delay=args.time_delay,
        time_threshold=args.time_threshold,
        confirmations=args.confirmations,
        oob_domain=args.oob_domain,
        oob_poll_url=args.oob_poll_url,
        scope_regex=args.scope_regex,
        mode=args.mode,
        src_path=args.src,
        raw_request=args.raw,
        os_type=args.os_type,
        impact=not args.no_impact,
        detectors=[d.strip() for d in args.detectors.split(",") if d.strip()],
    )

    try:
        result = Scanner(cfg).scan()
    except ScanError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    except (ValueError, OSError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    formatters = {"json": to_json, "md": to_markdown, "sarif": to_sarif}
    print(formatters[args.format](result))

    if args.output:
        if args.output.endswith(".md"):
            content = to_markdown(result)
        elif args.output.endswith(".sarif"):
            content = to_sarif(result)
        else:
            content = to_json(result)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"[+] report written to {args.output}", file=sys.stderr)

    return 1 if result.confirmed else 0


if __name__ == "__main__":
    raise SystemExit(main())
