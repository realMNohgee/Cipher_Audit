# Cipher_Audit 🔐

**A TLS cipher-suite policy auditor in pure Python.** Feed it a cipher list in `openssl ciphers -v` or nmap `ssl-enum-ciphers` style and it flags the weak and legacy suites — NULL, EXPORT, RC4, 3DES, single DES, CBC block ciphers (Lucky13 / SWEET32), anonymous DH, MD5 integrity, static RSA without forward secrecy, and PSK. Check a list against a Mozilla/NIST-style profile, or print the built-in weak-cipher reference table. Zero dependencies, Python standard library only.

## Why it exists

Every TLS misconfiguration is a version of the same mistake: a server left an old suite enabled for "compatibility". Cipher_Audit turns a raw cipher dump into a verdict — which suites are dangerous, why, and whether the list passes a modern policy — with no OpenSSL expertise required and JSON output an agent or a CI gate can consume.

## One tool, many domains

| Domain | What Cipher_Audit does for you |
|---|---|
| **Security / pentest** | Point it at an `ssl-enum-ciphers` dump and get the weak-suite findings, ranked by severity |
| **Compliance** | Check a scan against `modern` / `intermediate` / `old` profiles and get a pass/fail per suite |
| **DevOps / CI** | A non-zero exit on profile violations makes it a TLS-config regression gate |
| **Agentic AI** | Deterministic, machine-readable findings an LLM agent can cite without parsing prose |
| **Sysadmin** | `list` is a quick reference for *why* each weak category is weak |

## Install

```bash
git clone <your-fork-url> Cipher_Audit
cd Cipher_Audit
python3 Cipher_Audit.py --help
```

## Quick start

Pipe a cipher list straight in (openssl or nmap style):

```bash
printf 'ECDHE-RSA-AES256-GCM-SHA384 TLSv1.2 Kx=ECDH Au=RSA Enc=AESGCM(256) Mac=AEAD\nRC4-SHA SSLv3 Kx=RSA Au=RSA Enc=RC4(128) Mac=SHA1\n' \
  | python3 Cipher_Audit.py audit
```

```
Cipher_Audit — weak-suite report
Total: 2   Weak: 1   Clean: 1

  ok   ok     ECDHE-RSA-AES256-GCM-SHA384
  WEAK high   RC4-SHA [rc4, static-rsa]
```

### Audit a file as JSON

```bash
python3 Cipher_Audit.py audit ciphers.txt --format json
```

```json
{
  "total": 2,
  "weak": 1,
  "clean": 1,
  "findings": [
    {
      "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
      "weak": false,
      "severity": "ok",
      "categories": []
    },
    {
      "cipher": "RC4-SHA",
      "weak": true,
      "severity": "high",
      "categories": ["rc4", "static-rsa"]
    }
  ]
}
```

### Check a policy profile

```bash
python3 Cipher_Audit.py policy ciphers.txt --profile modern
```

```
Cipher_Audit — policy modern (TLS 1.3-era: AEAD + forward secrecy only)
Total: 2   Violations: 1   Compliant: 1

  PASS ECDHE-RSA-AES256-GCM-SHA384
  FAIL RC4-SHA (forbidden:rc4; forbidden:static-rsa)
```

Any violation makes `policy` exit non-zero, so it drops straight into a CI gate.

| Profile | Posture |
|---|---|
| `modern` | AEAD + forward secrecy only; forbids every weak category including CBC and PSK |
| `intermediate` | AEAD + forward secrecy; forbids CBC/3DES/static-RSA but tolerates PSK |
| `old` | Legacy interop: allows CBC, 3DES, and static RSA; still forbids NULL/EXPORT/RC4/DES/anon |

### The weak-cipher reference table

```bash
python3 Cipher_Audit.py list
```

```
Cipher_Audit — weak-cipher reference table

  null        NULL cipher           high  No encryption - plaintext on the wire
  export      EXPORT grade          high  40/56-bit export ciphers are trivially broken
  rc4         RC4 stream cipher     high  RC4 keystream biases (Bar Mitzvah / NOMORE)
  des         Single DES            high  56-bit key, brute-forceable in hours
  anon        Anonymous DH          high  No server authentication - open to MITM
  3des        3DES / Triple DES   medium  SWEET32 birthday attack on 64-bit blocks
  cbc         CBC block cipher    medium  Lucky13 padding oracle; avoid in modern profiles
  md5         MD5 integrity       medium  MD5 MAC - collision-prone
  static-rsa  Static RSA key exch medium  No forward secrecy (no ECDHE/DHE)
  psk         Pre-shared key         low  PSK suites - secure only with a strong key
```

## Accepted input

Cipher_Audit reads either common dump format, ignoring headers, graders, and nmap decoration:

```
# openssl ciphers -v
ECDHE-RSA-AES256-GCM-SHA384 TLSv1.2 Kx=ECDH Au=RSA Enc=AESGCM(256) Mac=AEAD

# nmap ssl-enum-ciphers
|   TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A
|   least strength: A
```

NULL and anonymous suites are matched on names like `NULL-SHA`, `ADH-AES256-SHA`, and `Au=None`.

## Subcommands

| Command | What it does |
|---|---|
| `audit [FILE]` | Flag weak/legacy suites in a file or on stdin |
| `policy FILE --profile modern\|intermediate\|old` | Check a cipher list against a profile |
| `list` | Print the built-in weak-cipher reference table |

Every subcommand accepts `--format text|json`.

## License

MIT — see [LICENSE](LICENSE).

---

🧰 **[Tool on Hermtica Marketplace](https://hermtica.com/marketplace)**
