# ExecProof

**Prove command execution. Don't guess it.**

ExecProof is a safe-by-design Python CLI that detects and **proves** OS command injection / RCE in web applications. It combines DAST — arithmetic canaries, nested-echo pairs, blind timing, OOB callbacks and SSTI escalation — with SAST (41 rules, 7 languages), then verifies impact by running `id` / `whoami` only after a finding is confirmed.

[![CI](https://github.com/abdelmhmoud2005/execproof/actions/workflows/ci.yml/badge.svg)](https://github.com/abdelmhmoud2005/execproof/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Design principles

- **Safe-by-design DAST**: arithmetic probes (`$((N*2))`), nested two-token echo (`echo A$(echo B)`), controlled `sleep()` timing, and OOB DNS callbacks. `rm`, `dd`, `wget`, `curl | sh`, etc. are hard-blocked.
- **Real impact proof**: on confirmed RCE the tool executes `id` and parses `uid=N(...)` from the response → finding confidence `impact-verified` (Gate-0-grade evidence, per hunt-rce methodology).
- **Anti-false-positive**: baseline-aware markers, repeatable time measurements, OOB candidates require an actual callback.
- **Scope enforcement**: `--scope-regex` fails every request outside scope.
- **Rate limiting**: `--rate` req/s, throttled client.

## Installation

```bash
git clone https://github.com/abdelmhmoud2005/execproof.git
cd execproof
pip install -e ".[dev]"
```

## DAST — dynamic scanning

```bash
# Reflected RCE + impact verification (executes `id`)
execproof scan -u "https://target.example/ping?host=127.0.0.1" --scope-regex 'target\.example$'

# Blind time-based
execproof scan -u "https://target.example/ping?host=8.8.8.8" \
  --detectors time --time-delay 6 --confirmations 2 --rate 3

# SSTI: fingerprint matrix (Jinja2/Twig/Freemarker/ERB/Thymeleaf/Velocity/Mako)
# then engine-specific RCE escalation (os.popen, Twig exec, ERB backticks, Freemarker Execute)
execproof scan -u "https://target.example/preview?tpl=invoice" --detectors ssti

# OOB with automatic confirmation (poll endpoint returning recent hits)
execproof scan -u "https://target.example/webhook?url=x" \
  --oob-domain abc123.oast.fun --oob-poll-url "https://mycollector/api/hits"

# Raw request replay (Burp copy/paste)
execproof scan -u "https://target.example" --raw request.txt

# Threading + Windows targets
execproof scan -u "https://target.example/run?cmd=x" --threads 4 --os windows
```

## SAST — static source analysis (40+ rules, 7 languages)

```bash
execproof scan --mode sast --src ./target-src
```

Languages & representative rules: Python (`os.system`, `shell=True`, `eval`, `yaml.load` w/o Loader, `pickle.loads`, `render_template_string`), PHP (`system/exec/backticks/eval/unserialize/include $var/phar://`), Java (`Runtime.exec`, `ProcessBuilder`, ScriptEngine/SpEL, `new Yaml()` w/o SafeConstructor, ObjectInputStream, JNDI), Node (`child_process.exec`, `eval`, `new Function`, `vm.*`, node-serialize), Ruby (`system`, backticks, `IO.popen`, `YAML.load`, `Marshal.load`, dynamic `send`), Go (`exec.Command`, `template.HTML`), C# (`Process.Start`, `BinaryFormatter`). Taint heuristic suppresses literal-only calls; every finding ships file:line + remediation.

## BOTH — merged report

```bash
execproof scan -u "https://target.example/run?cmd=x" --mode both --src ./target-src -o report.md
```

## Detectors

| Detector | Method | Confidence | Severity |
|----------|--------|------------|----------|
| `echo` | arithmetic eval + two-token nested echo | confirmed | critical |
| `impact` | executes `id` / `whoami`, parses output | impact-verified | critical |
| `time` | controlled `sleep N`, repeatable | confirmed / candidate | critical / high |
| `oob` | `nslookup TOKEN.<domain>` + optional poll | confirmed-with-poll / candidate | critical / high |
| `ssti` | engine fingerprint matrix → engine RCE payloads | confirmed / candidate | critical / high |
| `sast:*` | 40+ source rules | candidate | info–critical |

Injection syntaxes: raw, `; c ;`, `| c`, `|| c`, `&& c`, `$(c)`, `` `c` ``, newline (`%0a`), single/double-quote breakouts, and bypass layer. Contexts: query params, form bodies, JSON bodies.

## Output

Exit code: `0` clean, `1` confirmed, `2` config error. Formats: `json`, `md`, `sarif` (GitHub code-scanning compatible, `-o report.sarif`).

## Security & ethics

- Use **only** against explicitly authorized targets (program scope, own assets, signed engagements).
- The OOB detector reports *candidates* until your collector records the exact token.
- Impact stage only runs benign `id`/`whoami`.

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -q     # all tests run against a local vulnerable app on 127.0.0.1 (zero external traffic)
```

## Roadmap

- [ ] Interactsh native client (RSA poll protocol)
- [ ] Java/PHP deserialization blind probes (ysoserial URLDNS)
- [ ] Argument-injection vectors (Sonar table)
- [ ] SARIF rule taxonomy per SAST language
