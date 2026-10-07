#!/usr/bin/env python3
"""Cipher_Audit — a TLS cipher-suite policy auditor.

Feed it a cipher list in `openssl ciphers -v` or nmap `ssl-enum-ciphers` style
and it flags weak or legacy suites: NULL, EXPORT, RC4, 3DES, single DES, CBC
block ciphers (Lucky13 / SWEET32), anonymous DH, MD5 integrity, static RSA key
exchange, and PSK. Check a list against a Mozilla/NIST-style profile, or print
the built-in weak-cipher reference table.

Zero dependencies — Python standard library only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

# Weak-cipher reference table: (id, category, severity, note).
WEAK_TABLE = [
    ("null",       "NULL cipher",         "high",   "No encryption - plaintext on the wire"),
    ("export",     "EXPORT grade",        "high",   "40/56-bit export ciphers are trivially broken"),
    ("rc4",        "RC4 stream cipher",   "high",   "RC4 keystream biases (Bar Mitzvah / NOMORE)"),
    ("des",        "Single DES",          "high",   "56-bit key, brute-forceable in hours"),
    ("anon",       "Anonymous DH",        "high",   "No server authentication - open to MITM"),
    ("3des",       "3DES / Triple DES",   "medium", "SWEET32 birthday attack on 64-bit blocks"),
    ("cbc",        "CBC block cipher",    "medium", "Lucky13 padding oracle; avoid in modern profiles"),
    ("md5",        "MD5 integrity",       "medium", "MD5 MAC - collision-prone"),
    ("static-rsa", "Static RSA key exch", "medium", "No forward secrecy (no ECDHE/DHE)"),
    ("psk",        "Pre-shared key",      "low",    "PSK suites - secure only with a strong key"),
]

# Map a category id to its severity and severities to a comparable rank.
_SEV_BY_ID = {row[0]: row[2] for row in WEAK_TABLE}
_SEV_RANK = {"ok": 0, "low": 1, "medium": 2, "high": 3}

# Split a cipher string into uppercase tokens on any non-alphanumeric run.
_TOKEN_SPLIT = re.compile(r"[^A-Z0-9]+")
# AEAD indicators used by the profile feature check.
_AEAD_MARKERS = ("GCM", "CHACHA20", "POLY1305", "CCM")

# Lines that look like cipher entries start with an identifier token; these
# common non-cipher first tokens are rejected up front.
_DENY_FIRST = {"least", "strength", "ciphers", "port", "ssl", "tls", "sn", "cipher"}
_RE_CIPHERISH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,}$")
_RE_TLSVER = re.compile(r"^TLSv?\d", re.IGNORECASE)

# Mozilla/NIST-style profiles: forbidden category ids + required features.
PROFILES = {
    "modern": {
        "forbid": {"null", "export", "rc4", "des", "3des", "cbc", "md5",
                   "anon", "static-rsa", "psk"},
        "require": {"pfs", "aead"},
        "desc": "TLS 1.3-era: AEAD + forward secrecy only",
    },
    "intermediate": {
        "forbid": {"null", "export", "rc4", "des", "3des", "cbc", "md5",
                   "anon", "static-rsa"},
        "require": {"pfs", "aead"},
        "desc": "AEAD + forward secrecy, tolerates PSK",
    },
    "old": {
        "forbid": {"null", "export", "rc4", "des", "anon"},
        "require": set(),
        "desc": "Legacy interop: allows CBC, 3DES, static RSA",
    },
}


def _fail(msg, code=2):
    """Print a clear error to stderr and return a non-zero exit code."""
    print("error: " + msg, file=sys.stderr)
    return code


def _tokens(text):
    """Split cipher text into a set of uppercase tokens."""
    return set(t for t in _TOKEN_SPLIT.split(text.upper()) if t)


def _detect(cipher_text):
    """Return the set of weak-category ids that apply to one cipher entry."""
    up = cipher_text.upper()
    toks = _tokens(cipher_text)
    found = set()
    if "NULL" in toks:
        found.add("null")
    if "EXPORT" in toks or "EXPORT" in up:
        found.add("export")
    if "RC4" in toks or "ARCFOUR" in up:
        found.add("rc4")
    # Triple DES first, so a single-DES match is not double counted as 3DES.
    if ("3DES" in toks or "DES-CBC3" in up or "EDE3" in toks
            or "_3DES_" in up or "DES_EDE" in up):
        found.add("3des")
    # Single DES only when it is not part of a triple-DES name.
    if ("DES" in toks and "3DES" not in up
            and not ({"3DES", "EDE3", "CBC3", "DESX"} & toks)):
        found.add("des")
    # CBC detection covers both the "CBC" and "CBC3" tokens.
    if any(t.startswith("CBC") for t in toks):
        found.add("cbc")
    if ("ADH" in toks or "AECDH" in toks or "ANON" in up
            or "AU=NONE" in up or "AUTH=NONE" in up):
        found.add("anon")
    if "MD5" in toks:
        found.add("md5")
    # Static RSA: RSA key exchange with no ephemeral DH anywhere in the name.
    if (("RSA_WITH" in up and "ECDHE" not in toks and "DHE" not in toks)
            or ("KX=RSA" in up and "ECDHE" not in up and "DHE" not in up)):
        found.add("static-rsa")
    if "PSK" in toks:
        found.add("psk")
    return found


def _features(cipher_text):
    """Return the {pfs, aead} feature flags a profile can require."""
    up = cipher_text.upper()
    toks = _tokens(cipher_text)
    pfs = bool({"ECDHE", "DHE"} & toks) or "ECDHE" in up or "DHE-" in up
    aead = any(marker in up for marker in _AEAD_MARKERS)
    return {"pfs": pfs, "aead": aead}


def _worst_severity(cats):
    """Return the highest severity among a set of category ids (or 'ok')."""
    if not cats:
        return "ok"
    return max((_SEV_BY_ID.get(c, "low") for c in cats), key=lambda s: _SEV_RANK[s])


def _extract_cipher(line):
    """Pull the cipher identifier out of one openssl/nmap output line.

    Returns the cipher name string, or None if the line is not a cipher entry.
    """
    s = line.strip()
    if not s:
        return None
    # Drop nmap decorations ('|', '_', '-') and grade suffixes like ' - A'.
    s = s.lstrip("|_ -")
    s = s.split(" - ")[0].strip()
    parts = s.split()
    if not parts:
        return None
    first = parts[0]
    if first.lower() in _DENY_FIRST or _RE_TLSVER.match(first):
        return None
    if not _RE_CIPHERISH.match(first):
        return None
    return first


def _read_items(source):
    """Read cipher entries from a file path, or stdin when source is None/' - '.

    Returns a list of {'name', 'line'} dicts. Raises ValueError on
    missing/unreadable/empty input so the caller can exit non-zero.
    """
    if source in (None, "-"):
        if sys.stdin.isatty():
            raise ValueError("no input: pass a FILE or pipe a cipher list on stdin")
        lines = sys.stdin.read().splitlines()
    else:
        try:
            with open(source, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError as exc:
            raise ValueError("cannot read {}: {}".format(source, exc))
    entries = []
    for line in lines:
        name = _extract_cipher(line)
        if name:
            entries.append({"name": name, "line": line.strip()})
    if not entries:
        raise ValueError("no cipher entries found in input")
    return entries


def cmd_audit(args):
    """Flag weak/legacy suites in a cipher list (`audit`)."""
    try:
        entries = _read_items(args.file)
    except ValueError as exc:
        return _fail(str(exc))
    findings = []
    flagged = 0
    for e in entries:
        # Detect against the whole line so openssl Kx=/Au= metadata counts.
        cats = _detect(e["line"])
        if cats:
            flagged += 1
        findings.append({
            "cipher": e["name"],
            "weak": bool(cats),
            "severity": _worst_severity(cats),
            "categories": sorted(cats),
        })
    result = {
        "total": len(entries),
        "weak": flagged,
        "clean": len(entries) - flagged,
        "findings": findings,
    }
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Cipher_Audit — weak-suite report")
        print("Total: {}   Weak: {}   Clean: {}".format(
            result["total"], result["weak"], result["clean"]))
        print()
        for f in findings:
            mark = "WEAK" if f["weak"] else "ok  "
            extra = ("[" + ", ".join(f["categories"]) + "]") if f["categories"] else ""
            print("  {} {:6} {} {}".format(mark, f["severity"], f["cipher"], extra))
    return 0


def cmd_policy(args):
    """Check a cipher list against a profile (`policy`)."""
    prof = PROFILES[args.profile]
    try:
        entries = _read_items(args.file)
    except ValueError as exc:
        return _fail(str(exc))
    results = []
    violations = 0
    for e in entries:
        cats = _detect(e["line"])
        feats = _features(e["line"])
        problems = []
        for c in sorted(cats & prof["forbid"]):
            problems.append("forbidden:" + c)
        # A required feature that is absent is also a policy violation.
        for need in sorted(prof["require"]):
            if not feats[need]:
                problems.append("missing:" + need)
        ok = not problems
        if not ok:
            violations += 1
        results.append({"cipher": e["name"], "ok": ok, "problems": problems})
    result = {
        "profile": args.profile,
        "profile_desc": prof["desc"],
        "total": len(entries),
        "violations": violations,
        "compliant": len(entries) - violations,
        "results": results,
    }
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Cipher_Audit — policy {} ({})".format(args.profile, prof["desc"]))
        print("Total: {}   Violations: {}   Compliant: {}".format(
            result["total"], result["violations"], result["compliant"]))
        print()
        for r in results:
            mark = "PASS" if r["ok"] else "FAIL"
            extra = ("(" + "; ".join(r["problems"]) + ")") if r["problems"] else ""
            print("  {} {} {}".format(mark, r["cipher"], extra))
    # Non-zero exit when the list fails the profile: usable as a CI gate.
    return 0 if violations == 0 else 1


def cmd_list(args):
    """Print the built-in weak-cipher reference table (`list`)."""
    if args.format == "json":
        print(json.dumps({"weak_categories": [
            {"id": i, "category": c, "severity": s, "note": n}
            for i, c, s, n in WEAK_TABLE
        ]}, indent=2))
    else:
        print("Cipher_Audit — weak-cipher reference table")
        print()
        for i, c, s, n in WEAK_TABLE:
            print("  {:11} {:20} {:>6}  {}".format(i, c, s, n))
    return 0


def main(argv=None):
    # Shared parent parser: --format is attached to EVERY subcommand, never
    # to the top-level parser, so it is only valid after the subcommand name.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )

    parser = argparse.ArgumentParser(
        prog="Cipher_Audit",
        description="TLS cipher-suite policy auditor (stdlib only).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_audit = sub.add_parser(
        "audit", parents=[common],
        help="Flag weak/legacy suites in a cipher list")
    p_audit.add_argument("file", nargs="?", default=None,
                         help="Cipher list file (default: read stdin)")
    p_audit.set_defaults(func=cmd_audit)

    p_policy = sub.add_parser(
        "policy", parents=[common],
        help="Check a cipher list against a profile")
    p_policy.add_argument("file", help="Cipher list file")
    p_policy.add_argument("--profile", choices=["modern", "intermediate", "old"],
                          default="modern",
                          help="Policy profile (default: modern)")
    p_policy.set_defaults(func=cmd_policy)

    p_list = sub.add_parser(
        "list", parents=[common], help="Print the weak-cipher reference table")
    p_list.set_defaults(func=cmd_list)

    args = parser.parse_args(argv)  # parse exactly once
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
