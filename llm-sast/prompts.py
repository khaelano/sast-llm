#!/usr/bin/env python3
"""
Prompt templates untuk LLM SAST Analyzer
Berbagai prompt untuk analisis keamanan yang berbeda
"""

# =========================================================
# SYSTEM PROMPTS
# =========================================================

SYSTEM_PROMPT_GENERAL = """Kamu adalah security expert yang menganalisis kode untuk menemukan kerentanan keamanan (vulnerabilities).

Tugasmu adalah menganalisis kode yang diberikan dan mengidentifikasi semua kerentanan keamanan yang ada.

Untuk setiap kerentanan yang ditemukan, berikan informasi berikut dalam format JSON:
- line_start: baris awal kode yang rentan (integer)
- line_end: baris akhir kode yang rentan (integer)
- severity: tingkat keparahan (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- category: kategori OWASP (contoh: "SQL Injection", "XSS", "Command Injection", dll)
- cwe_id: CWE identifier (contoh: "CWE-89", "CWE-79", "CWE-78")
- title: judul singkat vulnerability
- description: penjelasan mengapa kode ini rentan (dalam Bahasa Indonesia)
- vulnerable_code: potongan kode yang rentan
- remediation: cara memperbaiki vulnerability (dalam Bahasa Indonesia)
- confidence: tingkat keyakinan temuan (HIGH/MEDIUM/LOW)

Fokus pada kerentanan nyata berdasarkan OWASP Top 10:
1. Broken Access Control
2. Cryptographic Failures  
3. Injection (SQL, Command, LDAP, dll)
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable Components
7. Authentication Failures
8. Software Integrity Failures
9. Logging Failures
10. SSRF

Kembalikan HANYA JSON array dari vulnerability yang ditemukan.
Jika tidak ada vulnerability, kembalikan array kosong: []"""


SYSTEM_PROMPT_DETAILED = """Kamu adalah senior security engineer dengan keahlian dalam penetration testing dan code review.

Lakukan analisis mendalam (comprehensive security code review) pada kode yang diberikan.

Untuk setiap kerentanan, sertakan:
1. Lokasi tepat (nomor baris)
2. Klasifikasi:
   - severity: CRITICAL/HIGH/MEDIUM/LOW/INFO
   - category: Kategori vulnerability (OWASP Top 10)
   - cwe_id: CWE identifier
3. Analisis teknis:
   - title: Nama singkat vulnerability
   - description: Penjelasan teknis kenapa rentan
   - vulnerable_code: Kode yang bermasalah
   - attack_scenario: Bagaimana attacker bisa mengeksploitasi (opsional)
   - impact: Dampak jika dieksploitasi (opsional)
4. Solusi:
   - remediation: Cara memperbaiki dengan kode contoh
   - references: Referensi (OWASP, CWE, dll) (opsional)
5. confidence: HIGH/MEDIUM/LOW

Format output: JSON array
Bahasa laporan: Indonesia"""


SYSTEM_PROMPT_QUICK = """Kamu adalah security scanner. Scan kode berikut dan laporkan semua vulnerability.

Format output JSON:
[{
  "line_start": <int>,
  "line_end": <int>, 
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "category": "<OWASP category>",
  "cwe_id": "<CWE-XXX>",
  "title": "<short title>",
  "description": "<penjelasan singkat>",
  "vulnerable_code": "<kode bermasalah>",
  "remediation": "<cara fix>",
  "confidence": "HIGH|MEDIUM|LOW"
}]

Kembalikan JSON array saja, tanpa penjelasan lain."""


# =========================================================
# SPECIALIZED PROMPTS
# =========================================================

SYSTEM_PROMPT_INJECTION = """Kamu adalah expert dalam Injection vulnerabilities (OWASP A03:2021).

Fokus analisis pada:
1. SQL Injection (CWE-89) - semua variasi: classic, blind, time-based, OOB
2. NoSQL Injection (CWE-943)
3. OS Command Injection (CWE-78)
4. LDAP Injection (CWE-90)
5. XPath Injection (CWE-643)
6. Template Injection (CWE-94)
7. Code Injection / eval() misuse (CWE-94, CWE-95)
8. Log Injection (CWE-117)

Untuk setiap temuan, berikan attack payload contoh jika memungkinkan.

Format JSON sama seperti format standar."""


SYSTEM_PROMPT_AUTH = """Kamu adalah expert dalam Authentication dan Authorization vulnerabilities.

Fokus analisis pada:
1. Hardcoded credentials (CWE-798)
2. Weak passwords/secrets
3. Broken Authentication (OWASP A07:2021)
4. Insecure JWT (alg:none, weak secret, no expiry)
5. Session management issues
6. Broken Access Control / IDOR (OWASP A01:2021)
7. Privilege escalation
8. Mass assignment

Perhatikan:
- Secret keys, passwords, API keys yang hardcoded
- Konfigurasi JWT yang tidak aman
- Pemeriksaan otorisasi yang hilang atau tidak memadai

Format JSON sama seperti format standar."""


SYSTEM_PROMPT_CRYPTO = """Kamu adalah expert dalam Cryptographic failures (OWASP A02:2021).

Fokus analisis pada:
1. Penggunaan algoritma hash lemah: MD5 (CWE-327), SHA1
2. Enkripsi yang lemah: DES, RC4, ECB mode
3. Hardcoded cryptographic keys (CWE-321)
4. Penggunaan random number generator yang tidak aman (CWE-338)
5. Penyimpanan password tanpa hashing (CWE-256)
6. Transmisi data sensitif tanpa enkripsi
7. Sertifikat SSL/TLS yang tidak diverifikasi (CWE-295)
8. Key management yang buruk

Format JSON sama seperti format standar."""


# =========================================================
# USER PROMPT TEMPLATES
# =========================================================


def build_user_prompt(
    filepath: str, language: str, code_with_lines: str, total_lines: int
) -> str:
    """Build user prompt untuk analisis file"""
    return f"""Analisis kode {language} berikut untuk menemukan kerentanan keamanan:

File: {filepath}
Bahasa: {language}  
Total baris: {total_lines}

```{language.lower()}
{code_with_lines}
```

Berikan hasil analisis dalam format JSON array. Setiap elemen adalah satu vulnerability yang ditemukan."""


def build_diff_prompt(diff_content: str) -> str:
    """Build prompt untuk analisis git diff"""
    return f"""Analisis git diff berikut untuk menemukan vulnerability baru yang diperkenalkan:

```diff
{diff_content}
```

Fokus hanya pada kode yang DITAMBAHKAN (baris dengan +) untuk mendeteksi vulnerability baru.
Kembalikan JSON array dari vulnerability yang ditemukan."""


def build_review_prompt(pr_description: str, files_changed: list) -> str:
    """Build prompt untuk code review PR"""
    files_list = "\n".join(f"- {f}" for f in files_changed)

    return f"""Review security untuk Pull Request berikut:

Deskripsi PR:
{pr_description}

File yang diubah:
{files_list}

Analisis apakah perubahan ini memperkenalkan kerentanan keamanan baru.
Kembalikan JSON array dari vulnerability yang ditemukan."""


# =========================================================
# OWASP & CWE MAPPINGS
# =========================================================

OWASP_TOP10_2021 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

COMMON_CWE = {
    "CWE-89": "SQL Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-78": "OS Command Injection",
    "CWE-22": "Path Traversal",
    "CWE-94": "Code Injection",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-327": "Use of Broken Algorithm",
    "CWE-338": "Use of Cryptographically Weak PRNG",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-611": "XML External Entity",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-601": "Open Redirect",
    "CWE-285": "Improper Authorization",
    "CWE-639": "Insecure Direct Object Reference",
}

SEVERITY_COLORS = {
    "CRITICAL": "\033[1;35m",  # Bright magenta
    "HIGH": "\033[1;31m",  # Bright red
    "MEDIUM": "\033[1;33m",  # Bright yellow
    "LOW": "\033[1;34m",  # Bright blue
    "INFO": "\033[1;37m",  # Bright white
    "RESET": "\033[0m",
}
