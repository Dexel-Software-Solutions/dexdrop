#!/usr/bin/env python3
"""
Dexdrop - Enterprise DevSecOps Security Scanner
===============================================

A zero-dependency, single-file static security scanner for source repositories.
It runs several analysers in parallel and produces console, JSON, SARIF 2.1.0
(GitHub Code Scanning / Azure DevOps compatible) and self-contained HTML reports.

Analysers
---------
* secrets      - provider tokens, credential URLs, quoted and unquoted (.env, YAML,
                 .properties) secret assignments with entropy filtering; always redacted
* python-sast  - AST analysis (import-alias aware, light taint tracking for SQL) for
                 injection, unsafe deserialisation, weak crypto, disabled TLS/JWT checks ...
* dockerfile   - base image pinning, root user, remote ADD, curl|sh, baked-in secrets
* iac          - Terraform / CloudFormation / Kubernetes misconfigurations
* ci           - GitHub Actions expression injection, permissions, unpinned actions
* dependencies - requirements files, pyproject.toml, npm/Python/Rust/Go/PHP lockfiles, optional OSV.dev lookup

Enterprise features
-------------------
* Stable fingerprints and baselines (adopt in legacy repos, fail only on new findings)
* Inline suppressions:  ``# dexdrop:ignore``  or  ``# dexdrop:ignore[PY-SHELL]``
* Project config file ``.dexdrop.json`` and ``--disable-rule``
* CWE mapping and remediation on every rule; quality-gate exit codes for CI/CD
* Transparent coverage: unparsable / oversized / unreadable files are reported, not hidden
* Built-in regression suite:  ``python dexdrop.py --self-test``

Usage
-----
    python dexdrop.py .                                   # scan current repo
    python dexdrop.py ./src --sarif out.sarif --html report.html
    python dexdrop.py . --online --fail-on medium         # + OSV advisories
    python dexdrop.py . --write-baseline .dexdrop-baseline.json
    python dexdrop.py . --baseline .dexdrop-baseline.json

Exit codes: 0 = gate passed, 1 = findings at/above --fail-on, 2 = usage/runtime error.
Run from the repository root so SARIF paths match your repo layout.

Only scan code you own or are authorised to assess.
"""

from __future__ import annotations

import abc
import argparse
import ast
import fnmatch
import hashlib
import html
import json
import logging
import math
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

# --------------------------------------------------------------------------- #
# Metadata
# --------------------------------------------------------------------------- #

__version__ = "1.3.0"
__author__ = "Demiyan Dissanayake"
__organization__ = "Dexel Software Solutions"
__github__ = "https://github.com/dexel-software-solutions"
__emails__ = ("demiyandissanayake@gmail.com", "dexelsoftwaresolutions@gmail.com")
__license__ = "Proprietary - (c) Dexel Software Solutions. All rights reserved."

TOOL_NAME = "Dexdrop"
CONFIG_FILENAME = ".dexdrop.json"
LOG = logging.getLogger("dexdrop")


class DexdropError(Exception):
    """User-facing error (bad config, unreadable baseline, ...). Mapped to exit code 2."""


# --------------------------------------------------------------------------- #
# Domain model
# --------------------------------------------------------------------------- #


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[str(value).strip().upper()]
        except KeyError as exc:
            choices = ", ".join(s.name.lower() for s in cls)
            raise argparse.ArgumentTypeError(f"invalid severity '{value}' (choose: {choices})") from exc

    @property
    def sarif_level(self) -> str:
        if self >= Severity.HIGH:
            return "error"
        return "warning" if self == Severity.MEDIUM else "note"

    @property
    def security_score(self) -> str:
        """Numeric score used by GitHub to bucket SARIF results."""
        return {4: "9.5", 3: "8.0", 2: "5.5", 1: "3.0", 0: "1.0"}[int(self)]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    category: str
    cwe: str
    remediation: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    path: str
    line: int
    message: str
    remediation: str
    cwe: str
    snippet: str
    fingerprint: str
    confidence: str = "high"

    def sort_key(self) -> Tuple[int, str, int, str]:
        return (-int(self.severity), self.path, self.line, self.rule_id)

    def to_dict(self) -> Dict[str, object]:
        data = asdict(self)
        data["severity"] = self.severity.name
        return data


@dataclass
class ScanResult:
    root: str
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    suppressed_inline: int = 0
    suppressed_baseline: int = 0
    duration_s: float = 0.0
    started_at: str = ""
    warnings: List[str] = field(default_factory=list)

    def counts(self) -> Dict[str, int]:
        counter = Counter(f.severity.name for f in self.findings)
        return {s.name: counter.get(s.name, 0) for s in sorted(Severity, reverse=True)}


# --------------------------------------------------------------------------- #
# Rule catalogue
# --------------------------------------------------------------------------- #

RULES: Dict[str, Rule] = {}


def _rule(rid: str, title: str, sev: Severity, cat: str, cwe: str, fix: str) -> None:
    RULES[rid] = Rule(rid, title, sev, cat, cwe, fix)


_S, _P, _D, _I, _C, _R = "secrets", "python-sast", "dockerfile", "iac", "ci", "dependencies"
_C_, _H_, _M_, _L_, _N_ = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO

# secrets
_rule("SEC-AWS-KEY", "AWS access key ID exposed", _C_, _S, "CWE-798", "Revoke the key in IAM, rotate, and load credentials from a secrets manager or workload identity.")
_rule("SEC-PRIVKEY", "Private key committed to source", _C_, _S, "CWE-321", "Remove the key from history, treat it as compromised, regenerate it and store it in a vault/KMS.")
_rule("SEC-GITHUB", "GitHub token exposed", _C_, _S, "CWE-798", "Revoke the token in GitHub settings and use short-lived tokens or GitHub Apps.")
_rule("SEC-GITLAB", "GitLab personal access token exposed", _C_, _S, "CWE-798", "Revoke the token in GitLab and inject secrets via CI variables.")
_rule("SEC-NPM", "npm access token exposed", _C_, _S, "CWE-798", "Revoke the token on npmjs.com and use granular, short-lived tokens.")
_rule("SEC-SENDGRID", "SendGrid API key exposed", _H_, _S, "CWE-798", "Delete the key in SendGrid and create a restricted replacement.")
_rule("SEC-AZURE", "Azure storage account key exposed", _C_, _S, "CWE-798", "Rotate the storage key and use managed identity or SAS tokens.")
_rule("SEC-SLACK", "Slack token exposed", _H_, _S, "CWE-798", "Revoke the token in Slack admin and inject it at runtime.")
_rule("SEC-GOOGLE", "Google API key exposed", _H_, _S, "CWE-798", "Restrict and rotate the key in Google Cloud Console; avoid committing it.")
_rule("SEC-STRIPE", "Stripe live secret key exposed", _C_, _S, "CWE-798", "Roll the key in the Stripe dashboard and load it from a secrets store.")
_rule("SEC-JWT", "JSON Web Token embedded in source", _M_, _S, "CWE-522", "Remove hard-coded tokens; if valid, revoke the session or signing key.")
_rule("SEC-URLCRED", "Credentials embedded in URL", _H_, _S, "CWE-798", "Move credentials out of connection strings into environment/secret stores.")
_rule("SEC-GENERIC", "Hard-coded credential or secret", _H_, _S, "CWE-798", "Replace the literal with an environment variable or secrets-manager lookup and rotate the value.")
# python
_rule("PY-EVAL", "Dynamic code execution via eval/exec", _H_, _P, "CWE-95", "Avoid eval/exec; use ast.literal_eval, a parser or an explicit dispatch table.")
_rule("PY-SHELL", "OS command execution through a shell", _H_, _P, "CWE-78", "Pass an argument list with shell=False and validate/escape any external input (shlex.quote).")
_rule("PY-DESER", "Unsafe deserialisation", _H_, _P, "CWE-502", "Never unpickle untrusted data; use JSON or a schema-validated format.")
_rule("PY-YAML", "yaml.load without a safe loader", _H_, _P, "CWE-502", "Use yaml.safe_load or pass Loader=yaml.SafeLoader.")
_rule("PY-WEAKHASH", "Weak hash algorithm (MD5/SHA-1)", _M_, _P, "CWE-328", "Use SHA-256+ for integrity and Argon2/bcrypt/scrypt for passwords; set usedforsecurity=False for non-security use.")
_rule("PY-TLS", "TLS certificate verification disabled", _H_, _P, "CWE-295", "Remove verify=False / check_hostname=False; trust a private CA bundle instead.")
_rule("PY-JWT", "JWT signature verification disabled", _C_, _P, "CWE-347", "Always verify signatures and pin the accepted algorithms.")
_rule("PY-SQLI", "SQL built from dynamic strings", _H_, _P, "CWE-89", "Use parameterised queries (placeholders) or an ORM; never concatenate/format SQL.")
_rule("PY-TEMP", "Insecure temporary file (tempfile.mktemp)", _M_, _P, "CWE-377", "Use tempfile.mkstemp, NamedTemporaryFile or TemporaryDirectory.")
_rule("PY-DEBUG", "Debug mode enabled", _H_, _P, "CWE-489", "Disable debug in production; drive it from configuration, default off.")
_rule("PY-XSS", "Template auto-escaping disabled", _M_, _P, "CWE-79", "Keep autoescape enabled (select_autoescape) and mark only vetted output as safe.")
_rule("PY-TAR", "Archive extraction without path filtering", _M_, _P, "CWE-22", "Use extractall(filter='data') (Py3.12+) or validate member paths before extracting.")
_rule("PY-WEAKCRYPTO", "Weak cipher or ECB mode", _H_, _P, "CWE-327", "Use AES-GCM or ChaCha20-Poly1305 from a vetted library.")
_rule("PY-XXE", "XML parsed with a non-hardened parser", _M_, _P, "CWE-611", "Use defusedxml (or disable DTD/entity resolution) for untrusted XML.")
# docker
_rule("DK-LATEST", "Base image not pinned to a version", _M_, _D, "CWE-1104", "Pin an explicit tag, ideally an immutable @sha256 digest.")
_rule("DK-ROOT", "Container runs as root", _M_, _D, "CWE-250", "Add a non-root USER and drop capabilities.")
_rule("DK-ADD-URL", "ADD fetches a remote URL", _M_, _D, "CWE-494", "Use curl/wget in RUN with checksum verification, or COPY a vetted artefact.")
_rule("DK-PIPE-SH", "Remote script piped into a shell", _H_, _D, "CWE-494", "Download, verify a checksum/signature, then execute.")
_rule("DK-SECRET", "Secret baked into image via ENV/ARG", _H_, _D, "CWE-798", "Use BuildKit secrets (--mount=type=secret) or runtime injection.")
_rule("DK-HEALTH", "No HEALTHCHECK defined", _L_, _D, "CWE-693", "Add a HEALTHCHECK so orchestrators can detect unhealthy containers.")
_rule("DK-APT", "apt-get install without --no-install-recommends", _N_, _D, "CWE-1104", "Add --no-install-recommends and clean apt lists to reduce attack surface.")
_rule("DK-SSH", "SSH port exposed", _M_, _D, "CWE-284", "Avoid running sshd in containers; use exec/attach tooling.")
_rule("DK-CHMOD", "World-writable permissions (chmod 777)", _M_, _D, "CWE-732", "Grant least-privilege permissions (e.g. 750/640).")
# iac
_rule("IAC-CIDR", "Unrestricted network range (0.0.0.0/0)", _M_, _I, "CWE-284", "Restrict ingress to known CIDRs, security groups or private endpoints.")
_rule("IAC-PUBACL", "Publicly readable storage ACL", _H_, _I, "CWE-732", "Use private ACLs and enable public-access-block.")
_rule("IAC-K8S-PRIV", "Privileged container / host namespace in manifest", _H_, _I, "CWE-250", "Drop privileged mode, set runAsNonRoot and allowPrivilegeEscalation: false.")
_rule("IAC-NOENC", "Encryption at rest disabled", _M_, _I, "CWE-311", "Enable encryption and manage keys with KMS.")
_rule("IAC-PUBDB", "Database publicly accessible", _H_, _I, "CWE-284", "Place the database in private subnets and disable public accessibility.")
_rule("IAC-IAMSTAR", "Wildcard IAM action", _H_, _I, "CWE-269", "Grant only the specific actions and resources required.")
# ci
_rule("CI-INJECT", "Untrusted GitHub event data in workflow expression", _H_, _C, "CWE-94", "Pass event data through an env var and reference it as a shell variable instead of inline ${{ }}.")
_rule("CI-PERMS", "Workflow grants write-all permissions", _M_, _C, "CWE-250", "Declare minimal per-job `permissions:` (default read-only).")
_rule("CI-UNPINNED", "Third-party action not pinned to a commit SHA", _L_, _C, "CWE-829", "Pin the action to a full-length commit SHA.")
_rule("CI-PRT", "pull_request_target trigger needs review", _M_, _C, "CWE-829", "Never check out/run untrusted PR code with this trigger's elevated token.")
# deps
_rule("DEP-UNPINNED", "Dependency not pinned to an exact version", _L_, _R, "CWE-1104", "Pin with == (and hashes) or use a lock file for reproducible, auditable builds.")
_rule("DEP-VULN", "Dependency has known vulnerabilities (OSV)", _M_, _R, "CWE-1395", "Upgrade to a fixed release; review advisories on https://osv.dev for exact severity.")

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_PLACEHOLDER_MARKERS = (
    "example", "changeme", "change_me", "placeholder", "your", "dummy", "sample",
    "xxxx", "****", "<", ">", "${", "{{", "%s", "todo", "redacted", "fake", "null", "none",
)
_MAX_SNIPPET = 160
_LOCKFILES = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "pipfile.lock",
    "go.sum", "cargo.lock", "composer.lock", "gemfile.lock",
})


def _basename(rel_path: str) -> str:
    return rel_path.rsplit("/", 1)[-1].lower()


def is_lockfile(rel_path: str) -> bool:
    return _basename(rel_path) in _LOCKFILES


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in Counter(value).values())


def is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def redact(secret: str) -> str:
    return f"{secret[:4]}***[{len(secret)} chars]" if len(secret) > 4 else "***"


def make_finding(
    rule_id: str,
    path: str,
    line: int,
    *,
    message: Optional[str] = None,
    snippet: str = "",
    basis: Optional[str] = None,
    confidence: str = "high",
) -> Finding:
    """Create a Finding from the rule catalogue with a stable fingerprint."""
    rule = RULES[rule_id]
    snippet = " ".join(snippet.split())[:_MAX_SNIPPET]
    seed = f"{rule_id}|{path}|{basis if basis is not None else snippet}"
    fingerprint = hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()[:32]
    return Finding(
        rule_id=rule.id, title=rule.title, severity=rule.severity, category=rule.category,
        path=path, line=max(line, 1), message=message or rule.title, remediation=rule.remediation,
        cwe=rule.cwe, snippet=snippet, fingerprint=fingerprint, confidence=confidence,
    )


# --------------------------------------------------------------------------- #
# Scanner interface
# --------------------------------------------------------------------------- #


class Scanner(abc.ABC):
    """Base class for all analysers. Implementations must be thread-safe."""

    name: str = "base"

    @abc.abstractmethod
    def accepts(self, rel_path: str) -> bool:
        """Return True if this analyser should inspect the file."""

    @abc.abstractmethod
    def scan(self, rel_path: str, text: str) -> Iterator[Finding]:
        """Yield findings for the file's text."""

    def notes(self) -> List[str]:
        """Coverage notes surfaced as warnings after the scan (e.g. unparsable files)."""
        return []


# --------------------------------------------------------------------------- #
# Secrets scanner
# --------------------------------------------------------------------------- #

_SECRET_PATTERNS: Sequence[Tuple[str, "re.Pattern[str]"]] = (
    ("SEC-AWS-KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("SEC-PRIVKEY", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    ("SEC-GITHUB", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("SEC-GITLAB", re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}")),
    ("SEC-NPM", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("SEC-SENDGRID", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("SEC-AZURE", re.compile(r"\bAccountKey=[A-Za-z0-9+/]{40,}={0,2}")),
    ("SEC-SLACK", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("SEC-GOOGLE", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("SEC-STRIPE", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{24,}\b")),
    ("SEC-JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
)
_URL_CRED_RE = re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@\"']*:(?P<value>[^/\s:@\"']{3,})@[^\s\"']+", re.I)
_NAME_KEYWORDS = r"(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token|private[_-]?key)"
# Quoted assignment, optionally type-annotated:  password: str = "..."  /  "token": "..."
_GENERIC_RE = re.compile(
    rf"(?P<name>[a-z0-9_.\-]*{_NAME_KEYWORDS}[a-z0-9_.\-]*)"
    r"[\"']?(?:\s*:\s*[A-Za-z_][\w\[\], .|]*)?\s*[:=]\s*[\"'](?P<value>[^\"'\s]{8,})[\"']",
    re.I,
)
# Unquoted assignment, only for config-style files (.env, YAML, .properties, ...)
_UNQUOTED_RE = re.compile(
    rf"^\s*(?:export\s+)?(?P<name>[a-z0-9_.\-]*{_NAME_KEYWORDS}[a-z0-9_.\-]*)\s*[=:]\s*"
    r"(?P<value>[^\s\"'#]{8,})\s*(?:#.*)?$",
    re.I,
)
_CONFIG_FILE_RE = re.compile(r"(?:^|/)(?:\.env(?:\.[^/]*)?|[^/]*\.(?:env|properties|ini|cfg|conf|toml|ya?ml))$", re.I)
_LOWER_IDENT_RE = re.compile(r"^[a-z_]+$")
_DOTTED_PATH_RE = re.compile(r"^\w+(?:\.\w+)+$")
_WORDY_RE = re.compile(r"^[a-z0-9]+(?:[-_./][a-z0-9]+)+$")  # db-credentials-secret, my/secret/path
_PASSWORDISH_RE = re.compile(r"pass|pwd", re.I)
_MAX_LINE_LEN = 5000  # beyond this only the cheap provider patterns run (minified bundles)
# Cheap literal gates: most lines contain none of these, so the expensive regexes are skipped.
_PROVIDER_GATE = re.compile(r"AKIA|ASIA|-----BEGIN|gh[pousr]_|github_pat_|glpat-|npm_|SG\.|AccountKey=|xox|AIza|_live_|eyJ")
_KEYWORD_GATE = re.compile(r"pass|pwd|secret|key|token", re.I)


class SecretScanner(Scanner):
    """Detects credentials with provider patterns plus entropy-filtered heuristics."""

    name = "secrets"
    ENTROPY_THRESHOLD = 3.0

    def accepts(self, rel_path: str) -> bool:
        return not is_lockfile(rel_path)

    def scan(self, rel_path: str, text: str) -> Iterator[Finding]:
        config_style = bool(_CONFIG_FILE_RE.search(rel_path))
        for lineno, line in enumerate(text.splitlines(), start=1):
            claimed: Set[str] = set()
            if _PROVIDER_GATE.search(line):
                for rule_id, pattern in _SECRET_PATTERNS:
                    for match in pattern.finditer(line):
                        secret = match.group(0)
                        if "EXAMPLE" in secret:
                            continue
                        claimed.add(secret)
                        yield self._finding(rule_id, rel_path, lineno, line, secret)
            if len(line) > _MAX_LINE_LEN:
                continue
            if "://" in line:
                for match in _URL_CRED_RE.finditer(line):
                    secret = match.group("value")
                    if not is_placeholder(secret) and not secret.startswith("$"):
                        claimed.add(secret)
                        yield self._finding("SEC-URLCRED", rel_path, lineno, line, secret)
            if not _KEYWORD_GATE.search(line):
                continue
            candidates = list(_GENERIC_RE.finditer(line))
            if config_style:
                unquoted = _UNQUOTED_RE.match(line)
                if unquoted:
                    candidates.append(unquoted)
            seen: Set[str] = set()
            for match in candidates:
                name, secret = match.group("name"), match.group("value")
                if secret in claimed or secret in seen or not self._looks_like_secret(name, secret):
                    continue
                seen.add(secret)
                yield self._finding("SEC-GENERIC", rel_path, lineno, line, secret,
                                    message=f"Possible hard-coded secret in '{name}'", confidence="medium")

    def _looks_like_secret(self, name: str, value: str) -> bool:
        if is_placeholder(value) or value[0] in "$!&*|>" or value.lower().startswith(("http://", "https://")):
            return False
        if _LOWER_IDENT_RE.match(value) or _DOTTED_PATH_RE.match(value) or _WORDY_RE.match(value):
            return False
        if len(set(value)) < 4:
            return False
        if _PASSWORDISH_RE.search(name):
            return True  # human-chosen passwords are low entropy by nature ("admin123")
        return shannon_entropy(value) >= self.ENTROPY_THRESHOLD

    @staticmethod
    def _finding(rule_id: str, path: str, lineno: int, line: str, secret: str,
                 message: Optional[str] = None, confidence: str = "high") -> Finding:
        snippet = line.strip()[:2000].replace(secret, redact(secret))
        digest = hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()
        return make_finding(rule_id, path, lineno, message=message, snippet=snippet,
                            basis=digest, confidence=confidence)


# --------------------------------------------------------------------------- #
# Python SAST (AST based)
# --------------------------------------------------------------------------- #

_SUBPROCESS_FUNCS = {"run", "call", "Popen", "check_call", "check_output"}
_ALWAYS_SHELL = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput",
                 "asyncio.create_subprocess_shell", "commands.getoutput"}
_DESER_FUNCS = {
    "pickle.load", "pickle.loads", "pickle.Unpickler", "cPickle.load", "cPickle.loads",
    "marshal.load", "marshal.loads", "dill.load", "dill.loads", "jsonpickle.decode",
}
_XML_FUNCS = {
    "xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring", "xml.etree.ElementTree.XML",
    "xml.dom.minidom.parse", "xml.dom.minidom.parseString", "xml.sax.parse", "xml.sax.parseString",
    "xml.dom.pulldom.parse", "xml.dom.pulldom.parseString", "lxml.etree.parse", "lxml.etree.fromstring",
}
_SQL_EXEC_ATTRS = {"execute", "executemany", "executescript"}
_WEAK_CIPHER_SUFFIXES = ("DES.new", "DES3.new", "ARC4.new", "ARC2.new", "Blowfish.new")
_SQL_KEYWORD_RE = re.compile(r"\b(?:select|insert|update|delete|drop|create|alter|truncate)\b", re.I)


def _dotted(node: ast.AST) -> str:
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _kw(call: ast.Call, name: str) -> Optional[ast.expr]:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _is_const(node: Optional[ast.AST], value: object) -> bool:
    return isinstance(node, ast.Constant) and node.value is value


def _is_str_const(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _dict_has(node: Optional[ast.AST], key: str, value: object) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    return any(isinstance(k, ast.Constant) and k.value == key and _is_const(v, value)
               for k, v in zip(node.keys, node.values))


def _is_dynamic_sql(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        sides = (node.left, node.right)
        return any(_is_str_const(s) or isinstance(s, ast.JoinedStr) for s in sides) and not all(
            isinstance(s, ast.Constant) for s in sides)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return _is_str_const(node.func.value)
    return False


def _string_pieces(node: ast.AST) -> str:
    return " ".join(n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str))


class _PyVisitor(ast.NodeVisitor):
    def __init__(self, rel_path: str, lines: Sequence[str]) -> None:
        self.rel_path = rel_path
        self.lines = lines
        self.aliases: Dict[str, str] = {}
        self.sql_literals: Set[str] = set()  # names bound to SQL-looking constant strings
        self.sql_dynamic: Set[str] = set()   # names bound to SQL built from dynamic parts
        self.findings: List[Finding] = []

    # -- plumbing ----------------------------------------------------------- #
    def emit(self, rule_id: str, node: ast.AST, message: Optional[str] = None, confidence: str = "high") -> None:
        lineno = getattr(node, "lineno", 1)
        snippet = self.lines[lineno - 1] if 0 < lineno <= len(self.lines) else ""
        self.findings.append(make_finding(rule_id, self.rel_path, lineno, message=message,
                                          snippet=snippet.strip(), confidence=confidence))

    def resolve(self, dotted: str) -> str:
        if not dotted:
            return dotted
        head, _, tail = dotted.partition(".")
        target = self.aliases.get(head)
        if target is None:
            return dotted
        return f"{target}.{tail}" if tail else target

    # -- imports ------------------------------------------------------------ #
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                root = alias.name.split(".")[0]
                self.aliases[root] = root

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and node.level == 0:
            for alias in node.names:
                self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    # -- statements --------------------------------------------------------- #
    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr == "MODE_ECB":
            self.emit("PY-WEAKCRYPTO", node, "ECB mode leaks plaintext patterns")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        value = node.value
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                if target.attr == "debug" and _is_const(value, True):
                    self.emit("PY-DEBUG", node)
                elif target.attr == "check_hostname" and _is_const(value, False):
                    self.emit("PY-TLS", node, "Hostname verification disabled (check_hostname=False)")
                elif target.attr == "verify_mode" and isinstance(value, ast.Attribute) and value.attr == "CERT_NONE":
                    self.emit("PY-TLS", node, "Certificate validation disabled (verify_mode=CERT_NONE)")
            elif isinstance(target, ast.Name):
                if target.id == "DEBUG" and _is_const(value, True):
                    self.emit("PY-DEBUG", node, "DEBUG = True (Django/Flask style setting)", confidence="medium")
                if _is_dynamic_sql(value) and _SQL_KEYWORD_RE.search(_string_pieces(value)):
                    self.sql_dynamic.add(target.id)
                elif _is_str_const(value) and _SQL_KEYWORD_RE.search(str(value.value)):  # type: ignore[attr-defined]
                    self.sql_literals.add(target.id)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if (isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add)
                and not isinstance(node.value, ast.Constant)
                and node.target.id in (self.sql_literals | self.sql_dynamic)):
            self.sql_dynamic.add(node.target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        fn = self.resolve(_dotted(node.func))
        attr = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        first = node.args[0] if node.args else None
        first_is_const = first is not None and _is_str_const(first)

        if fn in {"eval", "exec"} and first is not None and not isinstance(first, ast.Constant):
            self.emit("PY-EVAL", node, f"{fn}() called with a non-constant expression")

        if fn.startswith("subprocess.") and fn.split(".")[-1] in _SUBPROCESS_FUNCS and _is_const(_kw(node, "shell"), True):
            self.emit("PY-SHELL", node, "subprocess invoked with shell=True",
                      confidence="medium" if first_is_const else "high")
        elif fn in _ALWAYS_SHELL:
            self.emit("PY-SHELL", node, f"{fn}() executes through a shell",
                      confidence="medium" if first_is_const else "high")

        if fn in _DESER_FUNCS:
            self.emit("PY-DESER", node, f"{fn}() can execute arbitrary code on untrusted input")

        if fn in {"yaml.load", "yaml.load_all"}:
            loader = _kw(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
            if loader is None or "Safe" not in _dotted(loader):
                self.emit("PY-YAML", node)
        elif fn == "yaml.unsafe_load":
            self.emit("PY-YAML", node, "yaml.unsafe_load constructs arbitrary objects")

        if fn in {"hashlib.md5", "hashlib.sha1"} and not _is_const(_kw(node, "usedforsecurity"), False):
            self.emit("PY-WEAKHASH", node, f"{fn.split('.')[-1].upper()} is cryptographically broken")
        elif fn == "hashlib.new" and first_is_const and str(first.value).lower() in {"md5", "sha1"}:  # type: ignore[union-attr]
            self.emit("PY-WEAKHASH", node)

        if fn == "jwt.decode":
            if _is_const(_kw(node, "verify"), False) or _dict_has(_kw(node, "options"), "verify_signature", False):
                self.emit("PY-JWT", node, "jwt.decode called with signature verification disabled")
        elif _is_const(_kw(node, "verify"), False) or fn == "ssl._create_unverified_context":
            self.emit("PY-TLS", node)

        if attr in _SQL_EXEC_ATTRS and first is not None:
            if _is_dynamic_sql(first):
                self.emit("PY-SQLI", node, "SQL statement assembled with string formatting/concatenation")
            elif isinstance(first, ast.Name) and first.id in self.sql_dynamic:
                self.emit("PY-SQLI", node, f"Query variable '{first.id}' was built with string formatting/concatenation",
                          confidence="medium")

        if fn == "tempfile.mktemp":
            self.emit("PY-TEMP", node)
        if attr == "run" and _is_const(_kw(node, "debug"), True):
            self.emit("PY-DEBUG", node)
        if fn.endswith(("jinja2.Environment", "jinja2.Template")) and _is_const(_kw(node, "autoescape"), False):
            self.emit("PY-XSS", node)
        if attr == "extractall" and _kw(node, "filter") is None:
            self.emit("PY-TAR", node, confidence="low")
        if fn.endswith(_WEAK_CIPHER_SUFFIXES):
            self.emit("PY-WEAKCRYPTO", node, f"{fn.split('.')[-2]} is a deprecated cipher")
        if fn in _XML_FUNCS:
            self.emit("PY-XXE", node, f"{fn}() does not harden against entity expansion", confidence="medium")

        self.generic_visit(node)


class PythonScanner(Scanner):
    name = "python-sast"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._unparsable: List[str] = []

    def accepts(self, rel_path: str) -> bool:
        return rel_path.lower().endswith((".py", ".pyw"))

    def scan(self, rel_path: str, text: str) -> Iterator[Finding]:
        try:
            tree = ast.parse(text, filename=rel_path)
        except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
            LOG.debug("AST parse failed for %s: %s", rel_path, exc)
            with self._lock:
                self._unparsable.append(rel_path)
            return
        visitor = _PyVisitor(rel_path, text.splitlines())
        visitor.visit(tree)
        yield from visitor.findings

    def notes(self) -> List[str]:
        with self._lock:
            failed = sorted(self._unparsable)
        if not failed:
            return []
        shown = ", ".join(failed[:3]) + (" ..." if len(failed) > 3 else "")
        return [f"{len(failed)} Python file(s) could not be parsed and were NOT analysed by python-sast "
                f"(Python 2 or syntax errors): {shown}"]


# --------------------------------------------------------------------------- #
# Dockerfile scanner
# --------------------------------------------------------------------------- #

_SECRET_NAME_RE = re.compile(r"(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)", re.I)
_PIPE_SH_RE = re.compile(r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")
_CHMOD_RE = re.compile(r"\bchmod\s+(?:-R\s+)?0?777\b")
_ENV_PAIR_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(?:=|\s+)(\"[^\"]*\"|'[^']*'|\S+)")


def _docker_instructions(text: str) -> Iterator[Tuple[int, str, str]]:
    """Yield (line_no, INSTRUCTION, args) joining backslash continuations."""
    buffer: List[str] = []
    start = 0
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if stripped.startswith("#") or (not buffer and not stripped):
            continue
        if not buffer:
            start = lineno
        if stripped.endswith("\\"):
            buffer.append(stripped[:-1].strip())
            continue
        buffer.append(stripped)
        joined = " ".join(p for p in buffer if p)
        buffer = []
        instr, _, args = joined.partition(" ")
        yield start, instr.upper(), args.strip()
    if buffer:
        joined = " ".join(p for p in buffer if p)
        instr, _, args = joined.partition(" ")
        yield start, instr.upper(), args.strip()


class DockerfileScanner(Scanner):
    name = "dockerfile"

    def accepts(self, rel_path: str) -> bool:
        base = _basename(rel_path)
        return base == "dockerfile" or base.startswith("dockerfile.") or base.endswith(".dockerfile")

    def scan(self, rel_path: str, text: str) -> Iterator[Finding]:
        stages: Set[str] = set()
        last_from_line = 1
        current_user: Optional[str] = None
        has_healthcheck = False
        saw_from = False

        for lineno, instr, args in _docker_instructions(text):
            line_text = f"{instr} {args}"
            if instr == "FROM":
                saw_from = True
                last_from_line, current_user = lineno, None
                tokens = [t for t in args.split() if not t.startswith("--")]
                image = tokens[0] if tokens else ""
                alias = tokens[2].lower() if len(tokens) >= 3 and tokens[1].lower() == "as" else ""
                lowered = image.lower()
                if lowered and lowered != "scratch" and lowered not in stages and not image.startswith("$") and "@sha256:" not in lowered:
                    tag = image.rsplit("/", 1)[-1].partition(":")[2]
                    if not tag or tag.lower() == "latest":
                        yield make_finding("DK-LATEST", rel_path, lineno, snippet=line_text,
                                           message=f"Base image '{image}' uses an implicit or 'latest' tag")
                if alias:
                    stages.add(alias)
            elif instr == "USER":
                current_user = args.split()[0].split(":")[0] if args else None
            elif instr == "ADD" and re.match(r"(?:--\S+\s+)*https?://", args):
                yield make_finding("DK-ADD-URL", rel_path, lineno, snippet=line_text)
            elif instr == "RUN":
                if _PIPE_SH_RE.search(args):
                    yield make_finding("DK-PIPE-SH", rel_path, lineno, snippet=line_text)
                if _CHMOD_RE.search(args):
                    yield make_finding("DK-CHMOD", rel_path, lineno, snippet=line_text)
                if re.search(r"\bapt(?:-get)?\s+(?:-\S+\s+)*install\b", args) and "--no-install-recommends" not in args:
                    yield make_finding("DK-APT", rel_path, lineno, snippet=line_text)
            elif instr in {"ENV", "ARG"}:
                for name, value in _ENV_PAIR_RE.findall(args):
                    clean = value.strip("\"'")
                    if _SECRET_NAME_RE.search(name) and clean and not clean.startswith("$") and not is_placeholder(clean):
                        yield make_finding("DK-SECRET", rel_path, lineno,
                                           snippet=f"{instr} {name}={redact(clean)}",
                                           basis=f"{name}:{hashlib.sha256(clean.encode()).hexdigest()}",
                                           message=f"{instr} '{name}' embeds a secret value in the image layers")
            elif instr == "EXPOSE" and re.search(r"(?<!\d)22(?:/(?:tcp|udp))?(?!\d)", args):
                yield make_finding("DK-SSH", rel_path, lineno, snippet=line_text)
            elif instr == "HEALTHCHECK" and not args.upper().startswith("NONE"):
                has_healthcheck = True

        if saw_from:
            if current_user is None or current_user.lower() in {"root", "0"}:
                yield make_finding("DK-ROOT", rel_path, last_from_line,
                                   snippet="final stage has no non-root USER",
                                   message="Final image stage runs as root (no non-root USER set)")
            if not has_healthcheck:
                yield make_finding("DK-HEALTH", rel_path, 1, snippet="no HEALTHCHECK instruction", basis="no-healthcheck")


# --------------------------------------------------------------------------- #
# Infrastructure-as-Code scanner
# --------------------------------------------------------------------------- #

_IAC_EXT = (".tf", ".yaml", ".yml", ".json", ".template")
_IAC_PATTERNS: Sequence[Tuple[str, "re.Pattern[str]", str]] = (
    ("IAC-CIDR", re.compile(r"""(?i)(?:cidr_blocks?\s*=\s*\[[^\]]*["']0\.0\.0\.0/0["']|cidrip\s*:\s*["']?0\.0\.0\.0/0|"CidrIp"\s*:\s*"0\.0\.0\.0/0")"""), "medium"),
    ("IAC-PUBACL", re.compile(r"""(?i)(?:\bacl\s*[=:]\s*["']?public-read(?:-write)?|AccessControl\s*:\s*["']?PublicRead(?:Write)?)"""), "high"),
    ("IAC-K8S-PRIV", re.compile(r"^\s*(?:privileged|allowPrivilegeEscalation|hostNetwork|hostPID|hostIPC)\s*:\s*true\b|^\s*runAsUser\s*:\s*0\s*$"), "high"),
    ("IAC-NOENC", re.compile(r"(?i)\b(?:encrypted|storage_encrypted|enable_encryption|kms_encrypted)\s*=\s*false\b"), "high"),
    ("IAC-PUBDB", re.compile(r"(?i)\bpublicly_accessible\s*=\s*true\b"), "high"),
    ("IAC-IAMSTAR", re.compile(r"""(?i)(?:"Action"\s*:\s*"\*"|\bactions?\s*=\s*\[\s*"\*"\s*\])"""), "high"),
)


class IaCScanner(Scanner):
    name = "iac"

    def accepts(self, rel_path: str) -> bool:
        return (rel_path.lower().endswith(_IAC_EXT) and ".github/workflows/" not in rel_path
                and not is_lockfile(rel_path))

    def scan(self, rel_path: str, text: str) -> Iterator[Finding]:
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(line) > _MAX_LINE_LEN or line.lstrip().startswith(("#", "//")):
                continue
            for rule_id, pattern, confidence in _IAC_PATTERNS:
                if pattern.search(line):
                    yield make_finding(rule_id, rel_path, lineno, snippet=line.strip(), confidence=confidence)


# --------------------------------------------------------------------------- #
# CI/CD scanner (GitHub Actions)
# --------------------------------------------------------------------------- #

_GH_EXPR_RE = re.compile(
    r"\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|review_comment|pages|commits|head_commit|discussion)"
    r"[^}]*|head_ref)\s*\}\}")
_GH_USES_RE = re.compile(r"uses:\s*['\"]?(?P<owner>[\w.\-]+)/[\w.\-/]+@(?P<ref>[^\s'\"#]+)")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class CIScanner(Scanner):
    name = "ci"

    def accepts(self, rel_path: str) -> bool:
        return ".github/workflows/" in rel_path and rel_path.lower().endswith((".yml", ".yaml"))

    def scan(self, rel_path: str, text: str) -> Iterator[Finding]:
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _GH_EXPR_RE.search(line) and not stripped.startswith(("if:", "- if:", "name:")):
                yield make_finding("CI-INJECT", rel_path, lineno, snippet=stripped, confidence="medium")
            if re.match(r"permissions:\s*write-all\b", stripped):
                yield make_finding("CI-PERMS", rel_path, lineno, snippet=stripped)
            if re.search(r"\bpull_request_target\b", stripped):
                yield make_finding("CI-PRT", rel_path, lineno, snippet=stripped, confidence="low")
            match = _GH_USES_RE.search(line)
            if match and match.group("owner") not in {"actions", "github"} and not _SHA_RE.match(match.group("ref")):
                yield make_finding("CI-UNPINNED", rel_path, lineno, snippet=stripped,
                                   message=f"Action pinned to mutable ref '{match.group('ref')}'")


# --------------------------------------------------------------------------- #
# Dependency scanner (+ optional OSV.dev)
# --------------------------------------------------------------------------- #

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_REQ_LINE_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._\-]*)(?:\[[^\]]*\])?\s*(?P<spec>[^;#]*)")
_PIN_RE = re.compile(r"^===?\s*(?P<ver>[A-Za-z0-9_.!+\-]+)$")
_LOCK_KEY_RE = re.compile(r'^\s*"(node_modules/[^"]+)"\s*:\s*\{')

_Pkg = Tuple[str, str, str, str, int]  # ecosystem, name, version, path, line


def _norm_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class DependencyScanner(Scanner):
    name = "dependencies"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._packages: List[_Pkg] = []
        self._warnings: List[str] = []

    def _note(self, message: str) -> None:
        with self._lock:
            if message not in self._warnings:
                self._warnings.append(message)

    def notes(self) -> List[str]:
        with self._lock:
            return list(self._warnings)

    def accepts(self, rel_path: str) -> bool:
        base = _basename(rel_path)
        return base == "pyproject.toml" or is_lockfile(rel_path) or (
            base.endswith(".txt") and ("requirements" in base or base.startswith("constraints")))

    def scan(self, rel_path: str, text: str) -> Iterator[Finding]:
        base = _basename(rel_path)
        if base == "pyproject.toml":
            yield from self._scan_pyproject(rel_path, text)
            return
        if base == "gemfile.lock":
            self._collect_gemfile(rel_path, text)
            return
        if base == "package-lock.json":
            self._collect_npm(rel_path, text)
            return
        if base == "pipfile.lock":
            self._collect_pipfile(rel_path, text)
            return
        if base == "composer.lock":
            self._collect_composer(rel_path, text)
            return
        if base == "poetry.lock":
            self._collect_toml_lock(rel_path, text, "PyPI")
            return
        if base == "cargo.lock":
            self._collect_toml_lock(rel_path, text, "crates.io")
            return
        if base == "go.sum":
            self._collect_go_sum(rel_path, text)
            return
        if base == "yarn.lock":
            self._collect_yarn(rel_path, text)
            return
        if base == "pnpm-lock.yaml":
            self._collect_pnpm(rel_path, text)
            return
        # Other lockfile formats are intentionally not guessed at: a false
        # ecosystem/version mapping would make OSV results misleading.
        if is_lockfile(rel_path):
            self._note(f"{rel_path}: dependency lockfile format is recognised but not yet parsed; no OSV audit for it")
            return
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith(("#", "-", "git+", "http://", "https://", ".")):
                continue
            match = _REQ_LINE_RE.match(line)
            if not match:
                continue
            name = match.group("name")
            spec = re.split(r"\s--", match.group("spec"), maxsplit=1)[0]  # drop inline --hash=... options
            spec = spec.strip().rstrip("\\").strip()
            pin = _PIN_RE.match(spec)
            if pin and "*" not in pin.group("ver"):
                with self._lock:
                    self._packages.append(("PyPI", _norm_pkg(name), pin.group("ver"), rel_path, lineno))
            else:
                shown = spec or "(no version constraint)"
                yield make_finding("DEP-UNPINNED", rel_path, lineno, snippet=line,
                                   message=f"'{name}' is not pinned to an exact version: {shown}")

    def _scan_pyproject(self, path: str, text: str) -> Iterator[Finding]:
        """Inspect common PEP 621 and Poetry dependency declarations."""
        try:
            import tomllib  # Python 3.11+ standard library; keep Dexdrop dependency-free.
        except ImportError:
            self._note(f"{path}: pyproject.toml requires Python 3.11+ tomllib for dependency parsing; manifest not analysed")
            return
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError) as exc:
            self._note(f"{path}: invalid pyproject.toml; dependency manifest skipped ({exc})")
            return

        declarations: List[Tuple[str, str, int]] = []
        project = data.get("project", {})
        if isinstance(project, dict):
            for key in ("dependencies",):
                values = project.get(key, [])
                if isinstance(values, list):
                    declarations.extend((str(v), "PEP 621", 1) for v in values if isinstance(v, str))
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for values in optional.values():
                    if isinstance(values, list):
                        declarations.extend((str(v), "PEP 621 optional", 1) for v in values if isinstance(v, str))

        tool = data.get("tool", {})
        poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
        if isinstance(poetry, dict):
            for section_name in ("dependencies", "dev-dependencies"):
                section = poetry.get(section_name, {})
                if isinstance(section, dict):
                    for name, value in section.items():
                        if str(name).lower() == "python":
                            continue
                        spec = value.get("version", "") if isinstance(value, dict) else value
                        if isinstance(spec, str):
                            declarations.append((f"{name}{spec}", "Poetry", 1))
            groups = poetry.get("group", {})
            if isinstance(groups, dict):
                for group in groups.values():
                    if not isinstance(group, dict):
                        continue
                    deps = group.get("dependencies", {})
                    if isinstance(deps, dict):
                        for name, value in deps.items():
                            spec = value.get("version", "") if isinstance(value, dict) else value
                            if isinstance(spec, str):
                                declarations.append((f"{name}{spec}", "Poetry group", 1))

        seen: Set[Tuple[str, str]] = set()
        for declaration, source, line in declarations:
            declaration = declaration.strip()
            match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^]]+\])?\s*(.*)$", declaration)
            if not match:
                continue
            name, spec = match.group(1), match.group(2).strip()
            identity = (_norm_pkg(name), spec)
            if identity in seen:
                continue
            seen.add(identity)
            # Strip PEP 508 environment markers from the version requirement.
            spec_for_pin = spec.split(";", 1)[0].strip()
            pin = _PIN_RE.match(spec_for_pin)
            if pin and "*" not in pin.group("ver"):
                self._record("PyPI", _norm_pkg(name), pin.group("ver"), path, line)
            else:
                shown = spec or "(no version constraint)"
                yield make_finding("DEP-UNPINNED", path, line, snippet=declaration,
                                   message=f"'{name}' in {source} is not pinned to an exact version: {shown}")

    def _collect_gemfile(self, path: str, text: str) -> None:
        in_specs = False
        for lineno, raw in enumerate(text.splitlines(), 1):
            if raw.strip() == "specs:":
                in_specs = True
                continue
            if in_specs and raw and not raw[0].isspace() and raw.strip().endswith(":"):
                in_specs = False
            if not in_specs:
                continue
            match = re.match(r"^\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)", raw)
            if match:
                self._record("RubyGems", match.group(1), match.group(2), path, lineno)

    def _collect_npm(self, rel_path: str, text: str) -> None:
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, UnicodeError) as exc:
            self._note(f"{rel_path}: invalid package-lock.json; dependency audit skipped ({exc})")
            LOG.debug("invalid JSON in %s", rel_path)
            return
        if not isinstance(data, dict):
            self._note(f"{rel_path}: invalid package-lock.json structure; dependency audit skipped")
            return
        lines: Dict[str, int] = {}
        for idx, raw in enumerate(text.splitlines(), start=1):
            m = _LOCK_KEY_RE.match(raw)
            if m:
                lines[m.group(1)] = idx
        found: List[Tuple[str, str, int]] = []
        packages = data.get("packages")
        if isinstance(packages, dict):  # lockfile v2/v3
            for key, meta in packages.items():
                if key and isinstance(meta, dict) and "node_modules/" in key and not meta.get("link"):
                    name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
                    found.append((name, str(meta.get("version", "")), lines.get(key, 1)))
        else:  # lockfile v1
            def walk(deps: object) -> None:
                if not isinstance(deps, dict):
                    return
                for name, meta in deps.items():
                    if isinstance(meta, dict):
                        found.append((name, str(meta.get("version", "")), 1))
                        walk(meta.get("dependencies"))
            walk(data.get("dependencies"))
        with self._lock:
            for name, version, line in found:
                if re.match(r"^\d", version):
                    self._packages.append(("npm", name, version, rel_path, line))

    def _record(self, ecosystem: str, name: str, version: str, path: str, line: int) -> None:
        name, version = name.strip(), version.strip()
        # Go module versions are conventionally v-prefixed and OSV expects that
        # form; do not normalise versions globally across ecosystems.
        version_pattern = r"^v?[0-9][A-Za-z0-9.+_\-]*$" if ecosystem == "Go" else r"^[0-9][A-Za-z0-9.+_\-]*$"
        if name and version and re.match(version_pattern, version):
            with self._lock:
                self._packages.append((ecosystem, name, version, path, max(line, 1)))

    def _collect_pipfile(self, path: str, text: str) -> None:
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, UnicodeError) as exc:
            self._note(f"{path}: invalid Pipfile.lock JSON; dependency audit skipped ({exc})")
            return
        if not isinstance(data, dict):
            self._note(f"{path}: invalid Pipfile.lock structure; dependency audit skipped")
            return
        for section in ("default", "develop"):
            packages = data.get(section, {})
            if not isinstance(packages, dict):
                continue
            for name, meta in packages.items():
                if isinstance(meta, dict):
                    version = str(meta.get("version", ""))
                    if version.startswith("=="):
                        version = version[2:]
                    self._record("PyPI", _norm_pkg(name), version, path, 1)

    def _collect_composer(self, path: str, text: str) -> None:
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, UnicodeError) as exc:
            self._note(f"{path}: invalid composer.lock JSON; dependency audit skipped ({exc})")
            return
        if not isinstance(data, dict):
            self._note(f"{path}: invalid composer.lock structure; dependency audit skipped")
            return
        for section in ("packages", "packages-dev"):
            entries = data.get(section, [])
            if isinstance(entries, list):
                for item in entries:
                    if isinstance(item, dict):
                        version = str(item.get("version", "")).lstrip("v")
                        self._record("Packagist", str(item.get("name", "")), version, path, 1)

    def _collect_toml_lock(self, path: str, text: str, ecosystem: str) -> None:
        # A deliberately small TOML subset parser: only [[package]] records and
        # literal name/version fields are needed; no third-party TOML parser required.
        starts = list(re.finditer(r"(?m)^\[\[package\]\]\s*$", text))
        for i, match in enumerate(starts):
            end = starts[i + 1].start() if i + 1 < len(starts) else len(text)
            block = text[match.end():end]
            name_match = re.search(r'(?m)^name\s*=\s*"([^"\\]+)"', block)
            version_match = re.search(r'(?m)^version\s*=\s*"([^"\\]+)"', block)
            if name_match and version_match:
                line = text.count("\n", 0, match.start()) + 1
                name = _norm_pkg(name_match.group(1)) if ecosystem == "PyPI" else name_match.group(1)
                self._record(ecosystem, name, version_match.group(1), path, line)

    def _collect_go_sum(self, path: str, text: str) -> None:
        seen: Set[Tuple[str, str]] = set()
        for lineno, raw in enumerate(text.splitlines(), 1):
            parts = raw.split()
            if len(parts) < 3:
                continue
            module, version = parts[0], parts[1]
            if version.endswith("/go.mod"):
                continue
            pair = (module, version)
            if pair in seen:
                continue
            seen.add(pair)
            self._record("Go", module, version, path, lineno)

    def _collect_yarn(self, path: str, text: str) -> None:
        lines = text.splitlines()
        current_names: List[str] = []
        current_line = 1
        for lineno, raw in enumerate(lines + [""], 1):
            if raw and not raw[0].isspace() and raw.rstrip().endswith(":"):
                current_line = lineno
                header = raw.rstrip()[:-1]
                current_names = []
                # Yarn classic headers may contain multiple selectors separated by commas.
                for selector in re.findall(r'"([^"]+)"|([^,]+)', header):
                    item = (selector[0] or selector[1]).strip().strip('"')
                    item = re.sub(r"^npm:", "", item)
                    if "@" not in item:
                        continue
                    if item.startswith("@"):
                        split_at = item.find("@", 1)
                    else:
                        split_at = item.find("@")
                    if split_at > 0:
                        current_names.append(item[:split_at])
            version_match = re.match(r'^\s+version\s+"?([^"\s]+)"?', raw)
            if version_match and current_names:
                for name in current_names:
                    self._record("npm", name, version_match.group(1), path, current_line)
                current_names = []

    def _collect_pnpm(self, path: str, text: str) -> None:
        # Supports common pnpm v6-v9 package keys; parser intentionally avoids
        # interpreting importer/specifier sections as installed package versions.
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line.endswith(":") or line.startswith(("importers:", "packages:", "snapshots:", "settings:", "overrides:")):
                continue
            key = line[:-1].strip("'\"")
            key = re.sub(r"^/?", "", key)
            match = re.match(r"(?P<name>@[^/]+/[^/]+|[^/@][^/]*)/(?P<version>\d+[^(/]*)", key)
            if not match:
                match = re.match(r"(?P<name>@[^/]+/[^@]+|[^@]+)@(?P<version>\d+[^(/]*)", key)
            if match:
                self._record("npm", match.group("name"), match.group("version"), path, lineno)

    def audit_online(self, timeout: float = 20.0) -> Tuple[List[Finding], List[str]]:
        """Query OSV.dev for every pinned package. Network failures are non-fatal."""
        findings: List[Finding] = []
        warnings: List[str] = []
        with self._lock:
            packages = list(self._packages)
        unique = sorted({(e, n, v) for e, n, v, _, _ in packages})
        locations: Dict[Tuple[str, str, str], List[Tuple[str, int]]] = {}
        for eco, name, version, path, line in packages:
            locations.setdefault((eco, name, version), []).append((path, line))

        for offset in range(0, len(unique), 500):
            chunk = unique[offset:offset + 500]
            payload = {"queries": [{"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in chunk]}
            try:
                response = self._post(payload, timeout)
                results = response.get("results", []) if isinstance(response, dict) else None
                if not isinstance(results, list):
                    raise ValueError("OSV returned an unexpected response schema")
                if len(results) != len(chunk):
                    raise ValueError(
                        f"OSV returned {len(results)} results for {len(chunk)} package queries"
                    )
            except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
                warnings.append(f"OSV lookup incomplete; dependency advisories may NOT have been checked: {exc}")
                LOG.warning("OSV lookup failed or returned invalid data: %s", exc)
                break
            for (eco, name, version), result in zip(chunk, results):
                if not isinstance(result, dict):
                    warnings.append(f"OSV returned an invalid result for {eco}:{name}@{version}")
                    continue
                vulns = result.get("vulns", [])
                if not isinstance(vulns, list):
                    warnings.append(f"OSV returned invalid vulnerability data for {eco}:{name}@{version}")
                    continue
                ids = sorted(
                    str(v.get("id", "?")) for v in vulns if isinstance(v, dict)
                )
                if not ids:
                    continue
                label = f"{name}@{version}" if eco == "npm" else f"{name}=={version}"
                shown = ", ".join(ids[:5]) + (f" (+{len(ids) - 5} more)" if len(ids) > 5 else "")
                for path, line in locations[(eco, name, version)]:
                    findings.append(make_finding(
                        "DEP-VULN", path, line, snippet=label, basis=label,
                        message=f"{label} has {len(ids)} known advisories: {shown}"))
        return findings, warnings

    @staticmethod
    def _post(payload: Dict[str, object], timeout: float) -> Dict[str, object]:
        request = urllib.request.Request(
            OSV_BATCH_URL, data=json.dumps(payload).encode("utf-8"), method="POST",
            headers={"Content-Type": "application/json", "User-Agent": f"dexdrop/{__version__}"})
        last_exc: Optional[Exception] = None
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec - fixed https URL
                    # Bound untrusted network input before JSON parsing. A malformed or
                    # compromised upstream must not be able to consume unbounded memory.
                    max_response_bytes = 16 * 1024 * 1024
                    raw = response.read(max_response_bytes + 1)
                    if len(raw) > max_response_bytes:
                        raise ValueError(
                            f"OSV response exceeded the {max_response_bytes // (1024 * 1024)} MiB limit"
                        )
                    decoded = json.loads(raw.decode("utf-8"))
                    if not isinstance(decoded, dict):
                        raise ValueError("OSV response must be a JSON object")
                    return decoded
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_exc = exc
                time.sleep(0.5 * (2 ** attempt))
        raise last_exc  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #

DEFAULT_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__", ".tox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build", ".idea", ".vscode", ".terraform",
})
_BINARY_EXT = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".pdf", ".zip", ".gz", ".tar", ".tgz",
    ".7z", ".rar", ".jar", ".war", ".class", ".exe", ".dll", ".so", ".dylib", ".bin", ".woff", ".woff2",
    ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".pyc", ".pyo", ".whl", ".egg", ".sqlite", ".db",
})
_IGNORE_RE = re.compile(r"dexdrop:ignore(?:\[(?P<rules>[A-Za-z0-9_,\- ]+)\])?")
_COMMENT_PREFIXES = ("#", "//", "--", ";", "/*", "*")
_LOCKFILE_SIZE_LIMIT = 32 * 1024 * 1024


@dataclass(frozen=True)
class ScanConfig:
    root: Path
    excludes: Tuple[str, ...] = ()
    max_file_bytes: int = 1_048_576
    workers: int = 8
    online: bool = False


@dataclass
class _Outcome:
    findings: Optional[List[Finding]] = None  # None => file not analysed
    suppressed: int = 0
    warning: Optional[str] = None
    too_large: bool = False


class Engine:
    """Walks the tree, fans files out to analysers, applies suppressions."""

    def __init__(self, config: ScanConfig, scanners: Sequence[Scanner]) -> None:
        self.config = config
        self.scanners = list(scanners)
        self._walk_warnings: List[str] = []

    # -- file discovery ----------------------------------------------------- #
    def _rel(self, path: Path) -> str:
        if self.config.root.is_file():
            return path.name
        return path.relative_to(self.config.root).as_posix()

    def _excluded(self, rel: str) -> bool:
        name = rel.rsplit("/", 1)[-1]
        return any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(rel + "/", g) or fnmatch.fnmatch(name, g)
                   for g in self.config.excludes)

    def iter_files(self) -> Iterator[Path]:
        root = self.config.root
        if root.is_file():
            yield root
            return

        def on_error(exc: OSError) -> None:
            self._walk_warnings.append(f"cannot read directory '{exc.filename}': {exc.strerror}")

        for dirpath, dirnames, filenames in os.walk(root, onerror=on_error):
            base = Path(dirpath)
            dirnames[:] = sorted(
                d for d in dirnames
                if d not in DEFAULT_SKIP_DIRS and not self._excluded(self._rel(base / d)))
            for filename in sorted(filenames):
                path = base / filename
                if path.is_symlink() or path.suffix.lower() in _BINARY_EXT or self._excluded(self._rel(path)):
                    continue
                yield path

    # -- per-file work ------------------------------------------------------ #
    def _size_limit(self, rel: str) -> int:
        # Lockfiles can legitimately be much larger than source files. Apply the
        # same documented cap to every supported lockfile, not just npm's.
        if is_lockfile(rel):
            return max(self.config.max_file_bytes, _LOCKFILE_SIZE_LIMIT)
        return self.config.max_file_bytes

    def _scan_file(self, path: Path) -> _Outcome:
        try:
            return self._scan_file_unsafe(path)
        except Exception as exc:  # noqa: BLE001 - never let one file abort the whole scan
            LOG.exception("Unexpected failure scanning %s", path)
            return _Outcome(warning=f"{path}: unexpected error: {exc}")

    def _scan_file_unsafe(self, path: Path) -> _Outcome:
        rel = self._rel(path)
        applicable = [s for s in self.scanners if s.accepts(rel)]
        if not applicable:
            return _Outcome()
        try:
            if path.stat().st_size > self._size_limit(rel):
                return _Outcome(too_large=True)
            with path.open("rb") as handle:
                data = handle.read()
        except OSError as exc:
            return _Outcome(warning=f"{rel}: cannot read file: {exc.strerror or exc}")
        if b"\x00" in data[:4096]:
            return _Outcome()
        text = data.decode("utf-8", errors="replace")
        lines = text.splitlines()

        outcome = _Outcome(findings=[])
        for scanner in applicable:
            try:
                for finding in scanner.scan(rel, text):
                    if self._is_suppressed(lines, finding):
                        outcome.suppressed += 1
                    else:
                        outcome.findings.append(finding)  # type: ignore[union-attr]
            except Exception as exc:  # noqa: BLE001 - isolate analyser failures, keep the rest
                LOG.exception("Analyser %s crashed on %s", scanner.name, rel)
                outcome.warning = f"{rel}: analyser '{scanner.name}' failed: {exc}"
        return outcome

    @staticmethod
    def _is_suppressed(lines: Sequence[str], finding: Finding) -> bool:
        """Same-line marker, or a marker on a comment-only line directly above."""
        idx = finding.line - 1
        candidates: List[str] = []
        if 0 <= idx < len(lines):
            candidates.append(lines[idx])
        if 0 < idx <= len(lines) and lines[idx - 1].lstrip().startswith(_COMMENT_PREFIXES):
            candidates.append(lines[idx - 1])
        for text in candidates:
            match = _IGNORE_RE.search(text)
            if match:
                rules = match.group("rules")
                if not rules or finding.rule_id in {r.strip() for r in rules.split(",")}:
                    return True
        return False

    # -- orchestration ------------------------------------------------------ #
    def run(self) -> ScanResult:
        started = time.perf_counter()
        result = ScanResult(root=str(self.config.root.resolve()),
                            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        files = list(self.iter_files())
        too_large = 0
        with ThreadPoolExecutor(max_workers=max(1, self.config.workers)) as pool:
            for outcome in pool.map(self._scan_file, files):
                result.suppressed_inline += outcome.suppressed
                if outcome.warning:
                    result.warnings.append(outcome.warning)
                if outcome.too_large:
                    too_large += 1
                if outcome.findings is None:
                    result.files_skipped += 1
                    continue
                result.files_scanned += 1
                result.findings.extend(outcome.findings)

        if too_large:
            result.warnings.append(f"{too_large} file(s) exceeded the size limit and were NOT scanned "
                                   f"(raise --max-file-size-kb to include them)")
        result.warnings.extend(self._walk_warnings)
        for scanner in self.scanners:
            result.warnings.extend(scanner.notes())
        if self.config.online:
            for scanner in self.scanners:
                if isinstance(scanner, DependencyScanner):
                    dep_findings, dep_warnings = scanner.audit_online()
                    result.findings.extend(dep_findings)
                    result.warnings.extend(dep_warnings)

        result.findings = sorted(set(result.findings), key=Finding.sort_key)
        result.duration_s = round(time.perf_counter() - started, 3)
        return result


# --------------------------------------------------------------------------- #
# Baseline and project configuration
# --------------------------------------------------------------------------- #


def load_baseline(path: Path) -> Set[str]:
    """Load and validate a baseline without silently accepting malformed schemas."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DexdropError(f"cannot read baseline '{path}': {exc}") from exc
    if not isinstance(data, dict):
        raise DexdropError(f"invalid baseline '{path}': top-level value must be an object")
    fingerprints = data.get("fingerprints")
    if not isinstance(fingerprints, list) or not all(
        isinstance(item, str) and re.fullmatch(r"[0-9a-f]{32,64}", item) for item in fingerprints
    ):
        raise DexdropError(
            f"invalid baseline '{path}': 'fingerprints' must be a list of hexadecimal fingerprint strings"
        )
    return set(fingerprints)


def write_baseline(path: Path, findings: Iterable[Finding]) -> int:
    fingerprints = sorted({f.fingerprint for f in findings})
    payload = {"tool": TOOL_NAME, "version": __version__,
               "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "fingerprints": fingerprints}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return len(fingerprints)


_CONFIG_KEYS = {"exclude", "disable_rules", "min_severity", "fail_on", "max_file_size_kb"}


def load_config(root: Path) -> Dict[str, object]:
    """Load ``.dexdrop.json`` from the scan root (if present)."""
    path = (root if root.is_dir() else root.parent) / CONFIG_FILENAME
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DexdropError(f"invalid config '{path}': {exc}") from exc
    if not isinstance(data, dict):
        raise DexdropError(f"invalid config '{path}': top-level value must be an object")
    unknown = set(data) - _CONFIG_KEYS
    if unknown:
        LOG.warning("ignoring unknown config key(s) in %s: %s", path, ", ".join(sorted(unknown)))

    # Validate all supported settings here so bad configuration fails with a clear
    # user-facing message rather than an uncaught ValueError/TypeError mid-scan.
    for key in ("exclude", "disable_rules"):
        if key in data and (not isinstance(data[key], list) or not all(isinstance(v, str) for v in data[key])):
            raise DexdropError(f"config key '{key}' must be a list of strings")
    for key in ("min_severity", "fail_on"):
        if key in data:
            try:
                Severity.parse(str(data[key]))
            except argparse.ArgumentTypeError as exc:
                raise DexdropError(f"config key '{key}': {exc}") from exc
    if "max_file_size_kb" in data:
        value = data["max_file_size_kb"]
        # bool is an int subclass in Python, but is not a meaningful size setting.
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 1_048_576:
            raise DexdropError("config key 'max_file_size_kb' must be an integer between 1 and 1048576")
    return data


def _cfg_list(cfg: Dict[str, object], key: str) -> List[str]:
    value = cfg.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise DexdropError(f"config key '{key}' must be a list of strings")
    return value


def _cfg_severity(cfg: Dict[str, object], key: str, default: Severity) -> Severity:
    if key not in cfg:
        return default
    try:
        return Severity.parse(str(cfg[key]))
    except argparse.ArgumentTypeError as exc:
        raise DexdropError(f"config key '{key}': {exc}") from exc


# --------------------------------------------------------------------------- #
# Reporters
# --------------------------------------------------------------------------- #

_ANSI = {
    Severity.CRITICAL: "\033[1;97;41m", Severity.HIGH: "\033[1;31m", Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[1;36m", Severity.INFO: "\033[2;37m",
}
_RESET, _BOLD, _DIM = "\033[0m", "\033[1m", "\033[2m"


def developer_banner() -> str:
    return (f"{TOOL_NAME} v{__version__} - DevSecOps Security Scanner\n"
            f"Developed by {__author__} | {__organization__}\n"
            f"{__github__} | {__emails__[0]}")


def render_console(result: ScanResult, color: bool) -> str:
    def paint(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    out: List[str] = []
    for f in result.findings:
        tag = paint(_ANSI[f.severity], f" {f.severity.name} ")
        out.append(f"{tag} {paint(_BOLD, f.rule_id)}  {f.path}:{f.line}  {paint(_DIM, f'[{f.cwe}, {f.confidence} confidence]')}")
        out.append(f"    {f.message}")
        if f.snippet:
            out.append(f"    {paint(_DIM, '> ' + f.snippet)}")
        out.append(f"    {paint(_DIM, 'fix: ' + f.remediation)}")
        out.append("")
    if not result.findings:
        out.append("No findings at or above the reporting threshold.\n")
    counts = result.counts()
    summary = "  ".join(f"{paint(_ANSI[Severity[k]], k)}={v}" for k, v in counts.items())
    out.append(paint(_BOLD, "Summary"))
    out.append(f"  Findings  : {len(result.findings)}   ({summary})")
    out.append(f"  Files     : {result.files_scanned} scanned, {result.files_skipped} skipped")
    out.append(f"  Suppressed: {result.suppressed_inline} inline, {result.suppressed_baseline} baseline")
    out.append(f"  Duration  : {result.duration_s}s")
    for warning in result.warnings:
        out.append(paint(_ANSI[Severity.MEDIUM], f"  warning: {warning}"))
    return "\n".join(out)


def render_json(result: ScanResult) -> str:
    payload = {
        "tool": {"name": TOOL_NAME, "version": __version__, "developer": __author__, "organization": __organization__,
                 "github": __github__, "contact": list(__emails__)},
        "scan": {"root": result.root, "started_at": result.started_at, "duration_s": result.duration_s,
                 "files_scanned": result.files_scanned, "files_skipped": result.files_skipped,
                 "suppressed_inline": result.suppressed_inline, "suppressed_baseline": result.suppressed_baseline,
                 "warnings": result.warnings},
        "summary": result.counts(),
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(payload, indent=2)


def render_sarif(result: ScanResult) -> str:
    used = sorted({f.rule_id for f in result.findings})
    rules = [{
        "id": RULES[r].id, "name": RULES[r].id.replace("-", ""),
        "shortDescription": {"text": RULES[r].title},
        "help": {"text": RULES[r].remediation},
        "defaultConfiguration": {"level": RULES[r].severity.sarif_level},
        "properties": {"tags": ["security", RULES[r].category, RULES[r].cwe],
                       "security-severity": RULES[r].severity.security_score},
    } for r in used]
    results = [{
        "ruleId": f.rule_id, "level": f.severity.sarif_level,
        "message": {"text": f"{f.message} Fix: {f.remediation}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path},
                                            "region": {"startLine": f.line}}}],
        "partialFingerprints": {"dexdrop/v1": f.fingerprint},
        "properties": {"confidence": f.confidence, "cwe": f.cwe},
    } for f in result.findings]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": TOOL_NAME, "version": __version__, "informationUri": __github__,
                                      "organization": __organization__, "rules": rules}},
                  "results": results}],
    }
    return json.dumps(sarif, indent=2)


_HTML_CSS = """
:root{--bg:#f6f7f9;--fg:#14171a;--card:#fff;--mut:#5b6670;--bd:#dde1e6;--crit:#b3002d;--high:#d9480f;--med:#b7791f;--low:#0b7285;--info:#6c757d}
@media (prefers-color-scheme:dark){:root{--bg:#0f1317;--fg:#e6e9ec;--card:#171c22;--mut:#9aa5b1;--bd:#2a323b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 18px 60px}h1{margin:0 0 4px;font-size:26px}.sub{color:var(--mut);margin-bottom:22px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-bottom:26px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px;margin-bottom:12px}.cards .card{margin:0}.card b{display:block;font-size:26px}
.f{background:var(--card);border:1px solid var(--bd);border-left-width:5px;border-radius:10px;padding:14px 16px;margin-bottom:12px}
.f.CRITICAL{border-left-color:var(--crit)}.f.HIGH{border-left-color:var(--high)}.f.MEDIUM{border-left-color:var(--med)}.f.LOW{border-left-color:var(--low)}.f.INFO{border-left-color:var(--info)}
.badge{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;font-weight:700;color:#fff;margin-right:8px}
.badge.CRITICAL{background:var(--crit)}.badge.HIGH{background:var(--high)}.badge.MEDIUM{background:var(--med)}.badge.LOW{background:var(--low)}.badge.INFO{background:var(--info)}
code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}pre{background:var(--bg);border:1px solid var(--bd);border-radius:6px;padding:8px 10px;overflow-x:auto;margin:8px 0}
.mut{color:var(--mut)}.warn{border-left:5px solid var(--med)}footer{margin-top:36px;padding-top:16px;border-top:1px solid var(--bd);color:var(--mut);font-size:13px}a{color:inherit}
"""


def render_html(result: ScanResult) -> str:
    esc = html.escape
    cards = "".join(f'<div class="card"><span class="mut">{esc(k)}</span><b>{v}</b></div>' for k, v in result.counts().items())
    cards += (f'<div class="card"><span class="mut">FILES</span><b>{result.files_scanned}</b></div>'
              f'<div class="card"><span class="mut">SECONDS</span><b>{result.duration_s}</b></div>')
    body: List[str] = [f'<div class="card warn"><strong>Coverage warning:</strong> {esc(w)}</div>' for w in result.warnings]
    for f in result.findings:
        body.append(
            f'<div class="f {f.severity.name}"><span class="badge {f.severity.name}">{f.severity.name}</span>'
            f'<strong>{esc(f.rule_id)}</strong> &middot; {esc(f.title)}'
            f'<div class="mut"><code>{esc(f.path)}:{f.line}</code> &middot; {esc(f.cwe)} &middot; {esc(f.confidence)} confidence</div>'
            f'<p>{esc(f.message)}</p>'
            + (f'<pre>{esc(f.snippet)}</pre>' if f.snippet else "")
            + f'<div><strong>Fix:</strong> {esc(f.remediation)}</div></div>')
    if not result.findings:
        body.append('<div class="card">No findings. The gate is clean.</div>')
    emails = " &middot; ".join(f'<a href="mailto:{esc(e)}">{esc(e)}</a>' for e in __emails__)
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{TOOL_NAME} Security Report</title><style>{_HTML_CSS}</style></head><body><main>'
        f'<h1>{TOOL_NAME} Security Report</h1>'
        f'<div class="sub">Target <code>{esc(result.root)}</code> &middot; {esc(result.started_at)}</div>'
        f'<div class="cards">{cards}</div>{"".join(body)}'
        f'<footer>{TOOL_NAME} v{__version__} &middot; Developed by <strong>{esc(__author__)}</strong>, {esc(__organization__)}'
        f'<br><a href="{esc(__github__)}">{esc(__github__)}</a> &middot; {emails}</footer></main></body></html>')


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_scanners() -> List[Scanner]:
    return [SecretScanner(), PythonScanner(), DockerfileScanner(), IaCScanner(), CIScanner(), DependencyScanner()]


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"'{value}' is not an integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dexdrop", description=f"{TOOL_NAME} - enterprise DevSecOps security scanner.",
        epilog=f"Developed by {__author__} ({__organization__}) - {__github__} - {__emails__[0]}",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", nargs="?", default=".", help="file or directory to scan (default: .)")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="glob to exclude (repeatable)")
    parser.add_argument("--disable-rule", action="append", default=[], metavar="RULE_ID", help="disable a rule (repeatable)")
    parser.add_argument("--min-severity", type=Severity.parse, default=None, metavar="LEVEL",
                        help="lowest severity to report (default: low)")
    parser.add_argument("--fail-on", type=Severity.parse, default=None, metavar="LEVEL",
                        help="exit 1 when a finding at/above this level exists (default: high)")
    parser.add_argument("--exit-zero", action="store_true", help="report only; never fail the build")
    parser.add_argument("--online", action="store_true", help="query OSV.dev for known dependency vulnerabilities")
    parser.add_argument("--json", type=Path, metavar="FILE", help="write JSON report")
    parser.add_argument("--sarif", type=Path, metavar="FILE", help="write SARIF 2.1.0 report")
    parser.add_argument("--html", type=Path, metavar="FILE", help="write HTML report")
    parser.add_argument("--baseline", type=Path, metavar="FILE", help="suppress findings listed in this baseline")
    parser.add_argument("--write-baseline", type=Path, metavar="FILE", help="record current findings as baseline and exit 0")
    parser.add_argument("--max-file-size-kb", type=_positive_int, default=None, metavar="KB", help="skip larger files (default: 1024)")
    parser.add_argument("--workers", type=_positive_int, default=min(32, (os.cpu_count() or 2) + 4), help="scan threads")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    parser.add_argument("-q", "--quiet", action="store_true", help="no console report or banner")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("--list-rules", action="store_true", help="print the rule catalogue and exit")
    parser.add_argument("--self-test", action="store_true", help="run the built-in regression suite and exit")
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__} by {__author__}")
    return parser


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content + "\n", encoding="utf-8")


def _run(args: argparse.Namespace) -> int:
    if args.list_rules:
        for rule in sorted(RULES.values(), key=lambda r: (r.category, -int(r.severity), r.id)):
            print(f"{rule.id:<14} {rule.severity.name:<8} {rule.cwe:<9} {rule.category:<12} {rule.title}")
        return 0

    root = Path(args.path)
    if not root.exists():
        raise DexdropError(f"path not found: {root}")
    if not (root.is_file() or root.is_dir()):
        raise DexdropError(f"scan target must be a regular file or directory: {root}")

    cfg = load_config(root)
    disabled = set(_cfg_list(cfg, "disable_rules")) | set(args.disable_rule)
    unknown = sorted(disabled - set(RULES))
    if unknown:
        raise DexdropError(f"unknown rule id(s): {', '.join(unknown)} (see --list-rules)")
    min_severity = args.min_severity if args.min_severity is not None else _cfg_severity(cfg, "min_severity", Severity.LOW)
    fail_on = args.fail_on if args.fail_on is not None else _cfg_severity(cfg, "fail_on", Severity.HIGH)
    max_kb = args.max_file_size_kb if args.max_file_size_kb is not None else cfg.get("max_file_size_kb", 1024)
    if isinstance(max_kb, bool) or not isinstance(max_kb, int) or not 1 <= max_kb <= 1_048_576:
        raise DexdropError("max file size must be an integer between 1 and 1048576 KB")

    if not args.quiet:
        print(developer_banner() + "\n", file=sys.stderr)

    config = ScanConfig(root=root, excludes=tuple(_cfg_list(cfg, "exclude")) + tuple(args.exclude),
                        max_file_bytes=max_kb * 1024, workers=args.workers, online=args.online)
    result = Engine(config, build_scanners()).run()
    result = replace(result, findings=[f for f in result.findings if f.rule_id not in disabled])

    if args.write_baseline:
        try:
            count = write_baseline(args.write_baseline, result.findings)
        except OSError as exc:
            raise DexdropError(f"cannot write baseline '{args.write_baseline}': {exc}") from exc
        print(f"[dexdrop] baseline with {count} fingerprint(s) written to {args.write_baseline}", file=sys.stderr)
        return 0

    if args.baseline:
        known = load_baseline(args.baseline)
        kept = [f for f in result.findings if f.fingerprint not in known]
        result = replace(result, findings=kept, suppressed_baseline=len(result.findings) - len(kept))
    result = replace(result, findings=[f for f in result.findings if f.severity >= min_severity])

    try:
        if args.json:
            _write(args.json, render_json(result))
        if args.sarif:
            _write(args.sarif, render_sarif(result))
        if args.html:
            _write(args.html, render_html(result))
    except OSError as exc:
        raise DexdropError(f"cannot write report: {exc}") from exc

    if not args.quiet:
        use_color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
        print(render_console(result, use_color))

    if args.exit_zero:
        return 0
    return 1 if any(f.severity >= fail_on for f in result.findings) else 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass
    if args.self_test:
        return run_self_tests(verbose=args.verbose)
    try:
        return _run(args)
    except DexdropError as exc:
        print(f"[dexdrop] error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("[dexdrop] interrupted", file=sys.stderr)
        return 130


# --------------------------------------------------------------------------- #
# Built-in regression suite  (python dexdrop.py --self-test)
# --------------------------------------------------------------------------- #


def run_self_tests(verbose: bool = False) -> int:
    import contextlib
    import io
    import tempfile
    import unittest

    # Test fixtures deliberately contain vulnerable code; keywords are assembled at
    # runtime so Dexdrop can scan its own source without noise.
    PW = "pass" + "word"
    AWS = "AKIA" + "Z7XQ2LMN4PRT5VWB"

    def scan(scanner: Scanner, rel: str, text: str) -> List[Finding]:
        return list(scanner.scan(rel, text))

    def ids(findings: Iterable[Finding]) -> List[str]:
        return sorted(f.rule_id for f in findings)

    def run_cli(*argv: str) -> Tuple[int, str]:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            code = main(list(argv))
        return code, buf.getvalue()

    class SecretTests(unittest.TestCase):
        s = SecretScanner()

        def test_aws_key_detected_and_redacted(self) -> None:
            f = scan(self.s, "a.py", f'k = "{AWS}"')
            self.assertEqual(ids(f), ["SEC-AWS-KEY"])
            self.assertNotIn(AWS, f[0].snippet)

        def test_documented_example_key_ignored(self) -> None:
            self.assertEqual(scan(self.s, "a.py", 'k = "AKIAIOSFODNN7EXAMPLE"'), [])

        def test_unquoted_env_file_secret(self) -> None:
            self.assertEqual(ids(scan(self.s, ".env", f"DB_{PW.upper()}=Xk9mP2vL8qRz41")), ["SEC-GENERIC"])

        def test_env_placeholder_and_reference_ignored(self) -> None:
            text = f"DB_{PW.upper()}=changeme123\nAPI_TOKEN=${{TOKEN_FROM_CI}}\n"
            self.assertEqual(scan(self.s, ".env", text), [])

        def test_k8s_secret_name_not_flagged(self) -> None:
            self.assertEqual(scan(self.s, "k8s.yaml", "  secretName: db-credentials-secret\n"), [])

        def test_type_annotated_assignment(self) -> None:
            self.assertEqual(ids(scan(self.s, "c.py", f'{PW}: str = "Xk9#mP2$vL8qRz41"')), ["SEC-GENERIC"])

        def test_low_entropy_human_password(self) -> None:
            self.assertEqual(ids(scan(self.s, "c.py", f'{PW} = "Summer2024!"')), ["SEC-GENERIC"])

        def test_identifier_value_not_flagged(self) -> None:
            self.assertEqual(scan(self.s, "c.py", f'{PW}_field = "{PW}_hash"'), [])

        def test_minified_long_line_still_checked(self) -> None:
            line = "var a='" + "x" * 6000 + f"';k='{AWS}'"
            self.assertEqual(ids(scan(self.s, "m.js", line)), ["SEC-AWS-KEY"])

        def test_url_credentials(self) -> None:
            url = "postgres://app:" + "Zq81xLmP" + "@db.local/x"
            self.assertEqual(ids(scan(self.s, "c.py", f'u = "{url}"')), ["SEC-URLCRED"])

        def test_lockfiles_skipped(self) -> None:
            self.assertFalse(self.s.accepts("package-lock.json"))

    class PythonTests(unittest.TestCase):
        def sast(self, code: str) -> List[Finding]:
            return scan(PythonScanner(), "x.py", code)

        def test_alias_resolution(self) -> None:
            self.assertEqual(ids(self.sast("import subprocess as sp\nsp.run(c, shell=True)\n")), ["PY-SHELL"])
            self.assertEqual(ids(self.sast("from subprocess import run\nrun(c, shell=True)\n")), ["PY-SHELL"])

        def test_safe_patterns_clean(self) -> None:
            code = ("import yaml, hashlib, subprocess\nyaml.safe_load(x)\nyaml.load(x, Loader=yaml.SafeLoader)\n"
                    "hashlib.md5(b'x', usedforsecurity=False)\nsubprocess.run(['ls'])\ncur.execute('SELECT 1 WHERE a=%s', (a,))\n")
            self.assertEqual(self.sast(code), [])

        def test_sql_direct_and_via_variable(self) -> None:
            self.assertEqual(ids(self.sast('cur.execute(f"SELECT * FROM t WHERE a={a}")\n')), ["PY-SQLI"])
            code = 'q = "SELECT * FROM t WHERE a=" + a\ncur.execute(q)\n'
            self.assertEqual(ids(self.sast(code)), ["PY-SQLI"])
            code = 'q = "SELECT * FROM t WHERE 1=1"\nq += " AND a=" + a\ncur.execute(q)\n'
            self.assertEqual(ids(self.sast(code)), ["PY-SQLI"])

        def test_jwt_gets_its_own_rule(self) -> None:
            self.assertEqual(ids(self.sast("import jwt\njwt.decode(t, verify=False)\n")), ["PY-JWT"])
            code = 'import jwt\njwt.decode(t, key, options={"verify_signature": False})\n'
            self.assertEqual(ids(self.sast(code)), ["PY-JWT"])

        def test_tls_variants(self) -> None:
            self.assertEqual(ids(self.sast("requests.get(u, verify=False)\n")), ["PY-TLS"])
            self.assertEqual(ids(self.sast("ctx.check_hostname = False\n")), ["PY-TLS"])
            self.assertEqual(ids(self.sast("import ssl\nctx.verify_mode = ssl.CERT_NONE\n")), ["PY-TLS"])

        def test_debug_settings(self) -> None:
            self.assertEqual(ids(self.sast("DEBUG = True\n")), ["PY-DEBUG"])
            self.assertEqual(ids(self.sast("app.run(debug=True)\n")), ["PY-DEBUG"])

        def test_misc_rules(self) -> None:
            self.assertEqual(ids(self.sast("import pickle\npickle.loads(d)\n")), ["PY-DESER"])
            self.assertEqual(ids(self.sast("import tempfile\ntempfile.mktemp()\n")), ["PY-TEMP"])
            self.assertEqual(ids(self.sast("import xml.etree.ElementTree as ET\nET.fromstring(d)\n")), ["PY-XXE"])
            self.assertEqual(ids(self.sast("import subprocess\nsubprocess.getoutput(c)\n")), ["PY-SHELL"])

        def test_eval_constant_not_flagged(self) -> None:
            self.assertEqual(self.sast("eval('1+1')\n"), [])

        def test_unparsable_file_is_reported_not_hidden(self) -> None:
            scanner = PythonScanner()
            self.assertEqual(scan(scanner, "old.py", 'print "hi"\n'), [])
            self.assertIn("could not be parsed", scanner.notes()[0])

    class DockerTests(unittest.TestCase):
        d = DockerfileScanner()

        def test_multistage_root_and_pinning(self) -> None:
            text = "FROM python:3.12 AS build\nRUN x\nFROM build\nCOPY . /a\n"
            self.assertEqual(ids(scan(self.d, "Dockerfile", text)), ["DK-HEALTH", "DK-ROOT"])

        def test_hardened_dockerfile_clean(self) -> None:
            text = ("FROM python@sha256:" + "a" * 64 + "\nUSER app\nHEALTHCHECK CMD true\n")
            self.assertEqual(scan(self.d, "Dockerfile", text), [])

        def test_secret_and_pipe_sh(self) -> None:
            text = f"FROM a:1\nENV DB_{PW.upper()}=Zq81xLmP\nRUN curl -s http://x | sh\nUSER app\nHEALTHCHECK CMD true\n"
            self.assertEqual(ids(scan(self.d, "Dockerfile", text)), ["DK-PIPE-SH", "DK-SECRET"])

    class DependencyTests(unittest.TestCase):
        def test_hash_option_still_pinned(self) -> None:
            s = DependencyScanner()
            self.assertEqual(scan(s, "requirements.txt", "flask==2.0.1 --hash=sha256:abc\nrequests == 2.19.0\n"), [])
            self.assertEqual(len(s._packages), 2)

        def test_unpinned_flagged(self) -> None:
            f = scan(DependencyScanner(), "requirements.txt", "flask\nrequests>=2\n")
            self.assertEqual(ids(f), ["DEP-UNPINNED", "DEP-UNPINNED"])

        def test_package_lock_v3(self) -> None:
            lock = json.dumps({"lockfileVersion": 3, "packages": {
                "": {"name": "app"}, "node_modules/lodash": {"version": "4.17.20"},
                "node_modules/a/node_modules/b": {"version": "1.0.0"}}}, indent=2)
            s = DependencyScanner()
            scan(s, "package-lock.json", lock)
            self.assertEqual(sorted((p[1], p[2]) for p in s._packages), [("b", "1.0.0"), ("lodash", "4.17.20")])

        def test_pipfile_lock_parsed_for_osv(self) -> None:
            s = DependencyScanner()
            scan(s, "Pipfile.lock", json.dumps({"default": {"requests": {"version": "==2.31.0"}}, "develop": {}}))
            self.assertIn(("PyPI", "requests", "2.31.0", "Pipfile.lock", 1), s._packages)

        def test_poetry_and_cargo_lock_parsed(self) -> None:
            poetry = '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
            cargo = '[[package]]\nname = "serde"\nversion = "1.0.200"\n'
            s = DependencyScanner()
            scan(s, "poetry.lock", poetry)
            scan(s, "Cargo.lock", cargo)
            self.assertIn(("PyPI", "requests", "2.31.0", "poetry.lock", 1), s._packages)
            self.assertIn(("crates.io", "serde", "1.0.200", "Cargo.lock", 1), s._packages)

        def test_composer_lock_parsed(self) -> None:
            s = DependencyScanner()
            lock = json.dumps({"packages": [{"name": "symfony/http-kernel", "version": "v6.4.2"}], "packages-dev": []})
            scan(s, "composer.lock", lock)
            self.assertIn(("Packagist", "symfony/http-kernel", "6.4.2", "composer.lock", 1), s._packages)

        def test_go_sum_skips_go_mod_hash_rows(self) -> None:
            s = DependencyScanner()
            scan(s, "go.sum", "github.com/pkg/errors v0.9.1 h1:abc\ngithub.com/pkg/errors v0.9.1/go.mod h1:def\n")
            self.assertEqual(s._packages, [("Go", "github.com/pkg/errors", "v0.9.1", "go.sum", 1)])

        def test_yarn_and_pnpm_lock_parsed(self) -> None:
            s = DependencyScanner()
            scan(s, "yarn.lock", '"lodash@^4.17.0":\n  version "4.17.21"\n')
            scan(s, "pnpm-lock.yaml", "packages:\n  /lodash/4.17.21:\n    resolution: {}\n")
            pairs = {(p[0], p[1], p[2]) for p in s._packages}
            self.assertIn(("npm", "lodash", "4.17.21"), pairs)

        def test_pyproject_dependencies_pinned_and_unpinned(self) -> None:
            s = DependencyScanner()
            findings = scan(s, "pyproject.toml", '[project]\ndependencies = ["requests==2.31.0", "flask>=2.0"]\n')
            self.assertEqual(ids(findings), ["DEP-UNPINNED"])
            self.assertIn(("PyPI", "requests", "2.31.0", "pyproject.toml", 1), s._packages)

        def test_gemfile_lock_parsed(self) -> None:
            s = DependencyScanner()
            scan(s, "Gemfile.lock", "GEM\n  specs:\n    rails (7.1.2)\n      actionpack (>= 7.1.2)\n")
            self.assertIn(("RubyGems", "rails", "7.1.2", "Gemfile.lock", 3), s._packages)

        def test_osv_response_size_is_bounded(self) -> None:
            from unittest.mock import patch

            class FakeResponse:
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    return False
                def read(self, size: int = -1) -> bytes:
                    return b"x" * size

            with patch("urllib.request.urlopen", return_value=FakeResponse()):
                with self.assertRaisesRegex(ValueError, "exceeded.*limit"):
                    DependencyScanner._post({}, timeout=0.01)

    class EngineTests(unittest.TestCase):
        def project(self, files: Dict[str, str]) -> "tempfile.TemporaryDirectory[str]":
            tmp = tempfile.TemporaryDirectory()
            for name, content in files.items():
                p = Path(tmp.name) / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")
            self.addCleanup(tmp.cleanup)
            return tmp

        def run_engine(self, tmp: "tempfile.TemporaryDirectory[str]", **kw: object) -> ScanResult:
            return Engine(ScanConfig(root=Path(tmp.name), **kw), build_scanners()).run()  # type: ignore[arg-type]

        def test_suppression_scoping(self) -> None:
            code = ("import os\nos.system('a'+x)  # dexdrop:ignore\nos.system('b'+y)\n"
                    "# dexdrop:ignore[PY-SHELL]\nos.system('c'+z)\n"
                    "# dexdrop:ignore[PY-EVAL]\nos.system('d'+w)\n")
            r = self.run_engine(self.project({"a.py": code}))
            self.assertEqual(sorted(f.line for f in r.findings), [3, 7])  # line 3 must NOT inherit line 2's marker
            self.assertEqual(r.suppressed_inline, 2)

        def test_oversize_and_binary_handling(self) -> None:
            tmp = self.project({"big.py": "x = 1\n" * 2000, "ok.py": "eval(a)\n"})
            (Path(tmp.name) / "blob.dat").write_bytes(b"\x00\x01" * 100)
            r = self.run_engine(tmp, max_file_bytes=1000)
            self.assertTrue(any("size limit" in w for w in r.warnings))
            self.assertEqual(ids(r.findings), ["PY-EVAL"])

        def test_excludes_and_skip_dirs(self) -> None:
            tmp = self.project({"src/a.py": "eval(a)\n", "tests/t.py": "eval(a)\n", "node_modules/x.py": "eval(a)\n"})
            r = self.run_engine(tmp, excludes=("tests/*",))
            self.assertEqual([f.path for f in r.findings], ["src/a.py"])

        def test_fingerprint_stable_across_line_moves(self) -> None:
            a = self.run_engine(self.project({"a.py": "eval(a)\n"})).findings[0]
            b = self.run_engine(self.project({"a.py": "\n\n\neval(a)\n"})).findings[0]
            self.assertEqual(a.fingerprint, b.fingerprint)

        def test_all_supported_lockfiles_get_lockfile_size_cap(self) -> None:
            engine = Engine(ScanConfig(root=Path("."), max_file_bytes=1024), [])
            for name in _LOCKFILES:
                with self.subTest(name=name):
                    self.assertEqual(engine._size_limit(name), _LOCKFILE_SIZE_LIMIT)

    class CliTests(unittest.TestCase):
        def setUp(self) -> None:
            self.tmp = tempfile.TemporaryDirectory()
            self.addCleanup(self.tmp.cleanup)
            self.root = Path(self.tmp.name)
            (self.root / "app.py").write_text("eval(a)\n", encoding="utf-8")

        def test_exit_codes(self) -> None:
            self.assertEqual(run_cli(str(self.root), "-q")[0], 1)
            self.assertEqual(run_cli(str(self.root), "-q", "--fail-on", "critical")[0], 0)
            self.assertEqual(run_cli(str(self.root), "-q", "--exit-zero")[0], 0)
            self.assertEqual(run_cli(str(self.root / "missing"), "-q")[0], 2)

        def test_bad_baseline_is_error_not_finding_code(self) -> None:
            bad = self.root / "bad.json"
            bad.write_text("{nope", encoding="utf-8")
            self.assertEqual(run_cli(str(self.root), "-q", "--baseline", str(bad))[0], 2)

        def test_baseline_roundtrip(self) -> None:
            base = self.root / "base.json"
            self.assertEqual(run_cli(str(self.root), "-q", "--write-baseline", str(base))[0], 0)
            self.assertEqual(run_cli(str(self.root), "-q", "--baseline", str(base))[0], 0)

        def test_config_file_and_disable_rule(self) -> None:
            (self.root / CONFIG_FILENAME).write_text(json.dumps({"disable_rules": ["PY-EVAL"]}), encoding="utf-8")
            self.assertEqual(run_cli(str(self.root), "-q")[0], 0)
            (self.root / CONFIG_FILENAME).write_text("{broken", encoding="utf-8")
            self.assertEqual(run_cli(str(self.root), "-q")[0], 2)
            (self.root / CONFIG_FILENAME).unlink()
            self.assertEqual(run_cli(str(self.root), "-q", "--disable-rule", "NOPE")[0], 2)

        def test_reports_are_valid(self) -> None:
            out = self.root / "out"
            run_cli(str(self.root), "-q", "--json", str(out / "r.json"), "--sarif", str(out / "r.sarif"),
                    "--html", str(out / "r.html"))
            sarif = json.loads((out / "r.sarif").read_text(encoding="utf-8"))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "PY-EVAL")
            self.assertEqual(json.loads((out / "r.json").read_text(encoding="utf-8"))["tool"]["name"], "Dexdrop")

        def test_invalid_config_size_is_clean_error(self) -> None:
            (self.root / CONFIG_FILENAME).write_text(json.dumps({"max_file_size_kb": "large"}), encoding="utf-8")
            code, _ = run_cli(str(self.root), "-q")
            self.assertEqual(code, 2)
            (self.root / CONFIG_FILENAME).write_text(json.dumps({"max_file_size_kb": -5}), encoding="utf-8")
            code, _ = run_cli(str(self.root), "-q")
            self.assertEqual(code, 2)
            (self.root / CONFIG_FILENAME).write_text(json.dumps({"max_file_size_kb": True}), encoding="utf-8")
            code, _ = run_cli(str(self.root), "-q")
            self.assertEqual(code, 2)

        def test_invalid_baseline_schema_is_clean_error(self) -> None:
            bad = self.root / "bad-schema.json"
            bad.write_text(json.dumps({"fingerprints": "not-a-list"}), encoding="utf-8")
            self.assertEqual(run_cli(str(self.root), "-q", "--baseline", str(bad))[0], 2)
            bad.write_text(json.dumps({"fingerprints": ["not-a-fingerprint"]}), encoding="utf-8")
            self.assertEqual(run_cli(str(self.root), "-q", "--baseline", str(bad))[0], 2)

        def test_baseline_write_failure_is_clean_error(self) -> None:
            code, _ = run_cli(str(self.root), "-q", "--write-baseline", str(self.root))
            self.assertEqual(code, 2)

        def test_html_escapes_untrusted_content(self) -> None:
            finding = make_finding("PY-EVAL", "<b>.py", 1, snippet="<script>alert(1)</script>")
            page = render_html(ScanResult(root="<root>", findings=[finding], warnings=["<w>"]))
            self.assertNotIn("<script>alert", page)
            self.assertIn("&lt;script&gt;", page)
            self.assertIn(__author__, page)

    class CatalogueTests(unittest.TestCase):
        def test_every_rule_complete(self) -> None:
            for rule in RULES.values():
                self.assertTrue(rule.cwe.startswith("CWE-") and rule.remediation and rule.title, rule.id)

        def test_every_emitted_rule_exists(self) -> None:
            source = Path(__file__).read_text(encoding="utf-8")
            used = set(re.findall(r'"((?:SEC|PY|DK|IAC|CI|DEP)-[A-Z0-9-]+)"', source))
            self.assertEqual(sorted(used - set(RULES)), [])

    loader = unittest.TestLoader()
    suite = unittest.TestSuite(loader.loadTestsFromTestCase(c) for c in (
        SecretTests, PythonTests, DockerTests, DependencyTests, EngineTests, CliTests, CatalogueTests))
    runner = unittest.TextTestRunner(stream=sys.stderr, verbosity=2 if verbose else 1)
    return 0 if runner.run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
