from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .models import CANDIDATE, Finding

LANG_BY_EXT = {
    ".py": "python",
    ".php": "php",
    ".java": "java",
    ".kt": "java",
    ".js": "node",
    ".mjs": "node",
    ".ts": "node",
    ".rb": "ruby",
    ".go": "go",
    ".cs": "csharp",
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".tox", ".eggs"}

QUOTED = re.compile(r"'(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\"|`(?:\\.|[^`])*`")

INTERP = re.compile(r"#\{|\$\{|\$[a-zA-Z_]|%[sdif]")


@dataclass
class SastRule:
    rule_id: str
    pattern: re.Pattern
    severity: str
    description: str
    remediation: str
    taint_required: bool = True
    negative: re.Pattern | None = None


def R(rule_id, pattern, severity, description, remediation, taint_required=True, negative=None):
    return SastRule(rule_id, re.compile(pattern), severity, description, remediation,
                    taint_required, re.compile(negative) if negative else None)


RULES = {
    "python": [
        R("py-os-system", r"\bos\.system\s*\(", "critical",
          "os.system() builds a shell command string; user-controlled data in it allows command injection.",
          "Use subprocess.run([...list...], shell=False) and never interpolate user input."),
        R("py-os-popen", r"\bos\.popen\s*\(", "critical",
          "os.popen() runs the argument through /bin/sh -c.",
          "Use subprocess with a list argument and shell=False."),
        R("py-shell-true", r"shell\s*=\s*True", "critical",
          "subprocess with shell=True executes the command string via the shell.",
          "shell=False with a list of arguments; validate input with an allowlist."),
        R("py-eval", r"\beval\s*\(", "critical",
          "eval() executes arbitrary Python expressions from the argument.",
          "Avoid eval; use ast.literal_eval for literals or explicit parsing."),
        R("py-exec", r"\bexec\s*\(", "critical",
          "exec() executes arbitrary Python code from the argument.",
          "Remove exec; use a safe interpreter or explicit dispatch."),
        R("py-pickle", r"\bpickle\.loads?\s*\(|\bcPickle\.loads?\s*\(|\bmarshal\.loads?\s*\(",
          "critical", "Pickle/marshal deserialization of untrusted data is arbitrary code execution.",
          "Use JSON or another data-only format; never unpickle untrusted bytes.", False),
        R("py-yaml-load", r"\byaml\.load\s*\(", "critical",
          "yaml.load() without a safe loader can instantiate arbitrary objects (RCE).",
          "yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader).",
          False, negative=r"Loader\s*=|SafeLoader|CBaseLoader"),
        R("py-render-ts", r"\brender_template_string\s*\(", "high",
          "Flask render_template_string() on user input is Server-Side Template Injection.",
          "Pass variables as context; never template user data.", ),
        R("py-jinja-template", r"\bTemplate\s*\(", "high",
          "Direct Template( user_input ) instantiation is SSTI when input is user-controlled.",
          "Render fixed templates with variables as context."),
        R("py-popen-import", r"__import__\s*\(", "critical",
          "Dynamic import of attacker-influenced module names.",
          "Static imports only."),
    ],
    "php": [
        R("php-system", r"\b(system|shell_exec|passthru|proc_open|popen)\s*\(", "critical",
          "PHP shell execution function with interpolated input allows command injection.",
          "escapeshellarg() every user value; prefer non-shell APIs."),
        R("php-exec", r"\bexec\s*\(", "critical",
          "exec() runs the command via sh and appends output.",
          "escapeshellarg() or use PHP built-ins."),
        R("php-backtick", r"`[^`]+`", "critical",
          "Backtick operator executes the string as a shell command.",
          "Avoid backticks; escapeshellarg() user data."),
        R("php-eval", r"\beval\s*\(", "critical",
          "eval() executes arbitrary PHP code.",
          "Remove eval; use explicit logic."),
        R("php-unserialize", r"\bunserialize\s*\(", "critical",
          "unserialize() on user input enables object-injection RCE (POP chains).",
          "Use JSON; if unavoidable, allowed_classes=[] and validate."),
        R("php-lfi", r"(include|require)(_once)?\s*\(\s*\$", "critical",
          "include/require of a variable path enables LFI/RFI and RCE with uploads.",
          "Allowlist the file name map."),
        R("php-phar", r"phar://", "critical",
          "phar:// stream triggers unserialization on file ops.",
          "Block phar wrappers; validate paths."),
    ],
    "java": [
        R("java-runtime-exec", r"Runtime\.getRuntime\(\)\.exec\s*\(", "critical",
          "Runtime.exec() with a single string is split by the shell tokenizer; user data allows injection.",
          "Use exec(String[] cmdarray) with fixed argv."),
        R("java-processbuilder", r"new\s+ProcessBuilder\s*\(", "critical",
          "ProcessBuilder with user-derived argv allows argument injection.",
          "Allowlist argv values."),
        R("java-scriptengine", r"(ScriptEngine|GroovyShell|SpelExpressionParser|el\.ExpressionFactory)[^;]{0,40}\.(eval|parse|parseExpression)\s*\(",
          "critical", "Script/SpEL evaluation of user input is direct code execution.",
          "Sandbox the engine or use a static expression map."),
        R("java-yaml", r"new\s+Yaml\s*\(\s*\)", "critical",
          "SnakeYAML default constructor allows arbitrary type instantiation (CVE-2022-1471).",
          "new Yaml(new SafeConstructor()) or Yaml v2 with LoaderOptions limits.", False),
        R("java-objinput", r"ObjectInputStream|XMLDecoder", "critical",
          "Native Java deserialization of untrusted streams is RCE via gadget chains.",
          "Use a data-only format; filtering (JEP 290) is a mitigation, not a fix.", False),
        R("java-jndi", r"InitialContext\s*\(|lookup\s*\(\s*\"(ldap|rmi|dns)://", "critical",
          "JNDI lookup of user-influenced names enables remote class loading (Log4Shell family).",
          "Restrict lookup sources; set com.sun.jndi trustURLCodebase=false.", False),
    ],
    "node": [
        R("node-cp-exec", r"(child_process)?\.?exec\s*\(|execSync\s*\(|spawnSync\(.+shell\s*:\s*true",
          "critical", "child_process.exec runs the string through /bin/sh.",
          "Use execFile/spawn with an argv array and no shell."),
        R("node-eval", r"\beval\s*\(", "critical",
          "eval() executes arbitrary JS from input.",
          "JSON.parse or explicit parsing."),
        R("node-new-function", r"new\s+Function\s*\(", "critical",
          "new Function() compiles arbitrary JS at runtime.",
          "Remove dynamic compilation."),
        R("node-vm", r"vm\.runIn(This|New)Context\s*\(", "critical",
          "vm context is not a security boundary; user code escapes it.",
          "Isolated process or a real sandbox."),
        R("node-deserialize", r"node-serialize|serialize\.unserialize", "critical",
          "node-serialize unserialize executes IIFE payloads embedded in data.",
          "JSON only.", False),
    ],
    "ruby": [
        R("rb-system", r"\b(system|exec)\s*\(", "critical",
          "Kernel#system/exec run the string through the shell.",
          "Use system('cmd', arg1, arg2) list form with trusted args."),
        R("rb-backtick", r"`[^`]+`", "critical",
          "Backticks run the string via the shell and capture output.",
          "Open3.capture3 with argv array."),
        R("rb-popen", r"\bIO\.popen\s*\(|\bOpen3\.popen[23]?\w*\s*\(", "high",
          "Popen passes the string to the shell when given a single string.",
          "Pass argv as multiple arguments."),
        R("rb-yaml-load", r"\bYAML\.load\s*\(", "critical",
          "YAML.load (Psych) instantiates arbitrary Ruby objects.",
          "YAML.safe_load / YAML.parse with permitted classes.", False),
        R("rb-marshal", r"\bMarshal\.load\s*\(", "critical",
          "Marshal.load of untrusted data is arbitrary code execution.",
          "JSON.", False),
        R("rb-send", r"\.send\s*\(\s*[^\"']", "high",
          "Dynamic send() with a variable method name can invoke dangerous methods.",
          "Map user choices to fixed methods."),
        R("rb-eval", r"\beval\s*\(", "critical",
          "eval() executes arbitrary Ruby.",
          "Remove eval."),
    ],
    "go": [
        R("go-exec-command", r"exec\.Command\s*\(", "high",
          "exec.Command with a user-derived string as program/args.",
          "Fixed binary path; allowlist args."),
        R("go-template-html", r"template\.HTML\s*\(", "high",
          "template.HTML marks attacker data as safe HTML; combined with text/template it is an SSTI/XSS sink.",
          "Do not cast user data to template.HTML."),
        R("go-texexec", r"text/template|html/template", "info",
          "Template engine present; check that user input never becomes a template body.",
          "Parse fixed template files, render with variables.", False),
    ],
    "csharp": [
        R("cs-process-start", r"Process\.Start\s*\(", "critical",
          "Process.Start with a user-built command line.",
          "ProcessStartInfo with fixed FileName and ArgumentList."),
        R("cs-binformatter", r"BinaryFormatter", "critical",
          "BinaryFormatter deserialization is RCE (CVE family, unsupported).",
          "JSON; BinaryFormatter is deprecated.", False),
        R("cs-roslyn", r"CSharpScript|Roslyn|CompileAssemblyFrom", "critical",
          "Runtime compilation/execution of user text.",
          "Remove dynamic compilation.", False),
    ],
}


def _tainted(arg: str) -> bool:
    stripped = QUOTED.sub("", arg)
    return bool(re.search(r"[A-Za-z_$\\][A-Za-z0-9_$\\]*", stripped))


def _scan_line(rule: SastRule, line: str) -> bool:
    m = rule.pattern.search(line)
    if not m:
        return False
    if rule.negative and rule.negative.search(line):
        return False
    if rule.taint_required:
        region = line[m.start():]
        arg = line[m.end():]
        if INTERP.search(region):
            return True
        if not _tainted(arg):
            return False
    return True


def scan_file(path: str, lang: str) -> list:
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return findings
    for lineno, line in enumerate(lines, 1):
        for rule in RULES.get(lang, []):
            if _scan_line(rule, line):
                findings.append(Finding(
                    detector=f"sast:{rule.rule_id}",
                    injection_point=f"{path}:{lineno}",
                    payload=line.strip()[:200],
                    evidence=rule.description,
                    confidence=CANDIDATE,
                    severity=rule.severity,
                    detail=f"Remediation: {rule.remediation}",
                    source="sast",
                ))
    return findings


def scan_source_dir(root: str) -> list:
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            lang = LANG_BY_EXT.get(ext)
            if not lang:
                continue
            findings.extend(scan_file(os.path.join(dirpath, name), lang))
    return findings
