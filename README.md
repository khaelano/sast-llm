# Hands-On SAST: LLM vs Semgrep

Workshop membangun **Static Application Security Testing (SAST)** menggunakan LLM (DeepSeek), dibandingkan dengan **Semgrep** sebagai tool SAST berbasis aturan (rule-based).

---

## Struktur Proyek

```
hands-on-sast/
├── vulnerable-samples/          # Kode vulnerable untuk dianalisis
│   ├── python/
│   │   ├── sql_injection.py          # SQL Injection
│   │   ├── command_injection.py      # Command Injection
│   │   ├── path_traversal_secrets.py # Path Traversal, Hardcoded Secrets, Deserialization
│   │   └── ssrf_xxe.py               # SSRF, XXE, Open Redirect
│   └── javascript/
│       ├── app.js                    # SQL Injection, XSS, Command Injection
│       └── auth.js                   # JWT misuse, IDOR, Insecure Random
│
├── llm-sast/                    # LLM-based SAST tool
│   ├── analyzer.py                   # Main analyzer menggunakan DeepSeek API
│   └── prompts.py                    # Prompt templates
│
├── semgrep-sast/                # Semgrep configuration
│   ├── rules/
│   │   ├── python-security.yaml      # Custom rules untuk Python
│   │   └── javascript-security.yaml  # Custom rules untuk JavaScript
│   └── run_semgrep.sh                # Script runner
│
├── comparison/
│   └── compare.py                   # Comparison & HTML report generator
│
├── results/                     # Output (auto-generated)
│   ├── llm_results.json
│   ├── semgrep_full_results.json
│   └── comparison_report.html
│
└── run_all.py                   # Master runner
```

---

## Prasyarat

### 1. Python 3.14+

```bash
python3 --version
```

### 2. Install dependencies

```bash
# Using uv (recommended)
uv sync

# Or using pip
pip install openai python-dotenv rich pyyaml
```

### 3. Install Semgrep

```bash
pip install semgrep
# atau
brew install semgrep
```

### 4. DeepSeek API Key

Buat file `.env` di root proyek:

```bash
cp .env.example .env
# Edit .env: isi DEEPSEEK_API_KEY dengan API key kamu
```

API key akan otomatis di-load dari `.env` — tidak perlu `export` manual.

---

## Quick Start

### Jalankan semua (LLM + Semgrep + Perbandingan)

```bash
python run_all.py
```

### Jalankan hanya LLM SAST

```bash
python run_all.py --only-llm --model deepseek-v4-pro
```

### Jalankan hanya Semgrep

```bash
python run_all.py --only-semgrep
```

### Buat laporan perbandingan (dari hasil yang sudah ada)

```bash
python run_all.py --only-compare
```

---

## Workshop Step-by-Step

### MODUL 1: Memahami Vulnerable Code

Buka dan baca file-file sample berikut:

**Python vulnerabilities:**
- `vulnerable-samples/python/sql_injection.py` — SQL Injection (CWE-89)
- `vulnerable-samples/python/command_injection.py` — Command Injection (CWE-78)
- `vulnerable-samples/python/path_traversal_secrets.py` — Path Traversal + Hardcoded Secrets
- `vulnerable-samples/python/ssrf_xxe.py` — SSRF + XXE

**JavaScript vulnerabilities:**
- `vulnerable-samples/javascript/app.js` — SQL Injection, XSS, Command Injection
- `vulnerable-samples/javascript/auth.js` — JWT misuse, Hardcoded secrets, IDOR

> Perhatikan pola kode yang VULNERABLE vs yang SECURE dalam setiap file.

---

### MODUL 2: Menjalankan LLM SAST

#### 2.1 Analisis satu file

```bash
python llm-sast/analyzer.py \
  --file vulnerable-samples/python/sql_injection.py \
  --model deepseek-v4-pro \
  --output results/llm_sql.json
```

#### 2.2 Analisis seluruh direktori

```bash
python llm-sast/analyzer.py \
  --dir vulnerable-samples/ \
  --model deepseek-v4-pro \
  --output results/llm_results.json
```

#### 2.3 Gunakan model yang lebih cepat

```bash
python llm-sast/analyzer.py \
  --dir vulnerable-samples/ \
  --model deepseek-v4-flash \
  --output results/llm_results_flash.json
```

#### 2.4 Lihat hasil

```bash
cat results/llm_results.json | python3 -m json.tool | head -100
```

**Contoh output LLM:**

```json
{
  "tool": "LLM SAST Analyzer",
  "total_vulnerabilities": 23,
  "results": [
    {
      "file": "sql_injection.py",
      "vulnerabilities": [
        {
          "line_start": 17,
          "line_end": 19,
          "severity": "CRITICAL",
          "category": "SQL Injection",
          "cwe_id": "CWE-89",
          "title": "SQL Injection via String Concatenation",
          "description": "Input pengguna digabungkan langsung ke dalam query SQL...",
          "remediation": "Gunakan parameterized query: cursor.execute('...WHERE id = ?', (id,))",
          "confidence": "HIGH"
        }
      ]
    }
  ]
}
```

---

### MODUL 3: Menjalankan Semgrep

#### 3.1 Scan dengan OWASP Top 10 rules

```bash
semgrep --config p/owasp-top-ten \
  --output results/semgrep_owasp.json \
  --json \
  vulnerable-samples/
```

#### 3.2 Scan dengan rules Python

```bash
semgrep --config p/python \
  --output results/semgrep_python.json \
  --json \
  vulnerable-samples/python/
```

#### 3.3 Scan dengan custom rules kita

```bash
semgrep --config semgrep-sast/rules/ \
  --output results/semgrep_custom.json \
  --json \
  vulnerable-samples/
```

#### 3.4 Scan lengkap (semua rules)

```bash
bash semgrep-sast/run_semgrep.sh
```

#### 3.5 Output teks (langsung di terminal)

```bash
semgrep --config p/owasp-top-ten vulnerable-samples/
```

**Contoh output Semgrep:**

```
vulnerable-samples/python/sql_injection.py
  sql-injection-f-string (line 28)
  ❯ VULNERABILITY: f-string digunakan dalam query SQL.
  
  17┆ query = "SELECT * FROM users WHERE username = '" + username + "'"
```

---

### MODUL 4: Membandingkan Hasil

```bash
python comparison/compare.py \
  --llm results/llm_results.json \
  --semgrep results/semgrep_full_results.json \
  --output results/comparison_report.html
```

Kemudian buka laporan HTML di browser:

```bash
open results/comparison_report.html
```

---

### MODUL 5: Membuat Custom Rule Semgrep

Buat file `semgrep-sast/rules/my-custom-rule.yaml`:

```yaml
rules:
  - id: my-custom-sql-injection
    pattern: |
      $CURSOR.execute($QUERY + $USER_INPUT)
    message: "SQL Injection: jangan gabungkan input user ke query!"
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-89"
```

Test rule:

```bash
semgrep --config semgrep-sast/rules/my-custom-rule.yaml vulnerable-samples/python/
```

---

## Perbandingan LLM vs Semgrep

| Aspek | LLM SAST | Semgrep |
|-------|----------|---------|
| **Kecepatan** | Lambat (API call) | Sangat cepat |
| **Biaya** | Berbayar per token | Gratis (OSS) |
| **Pattern Matching** | Kontekstual/semantik | Rule-based exact |
| **False Positives** | Mungkin ada (hallucination) | Sangat rendah |
| **Penjelasan** | Sangat detail & kontekstual | Terbatas |
| **Remediation** | Kontekstual dengan contoh | Generic |
| **Bahasa Support** | Semua bahasa | 40+ bahasa |
| **CI/CD Integration** | Kompleks | Native & mudah |
| **Offline** | Tidak (butuh API) | Ya |
| **Reprodusibilitas** | Tidak selalu konsisten | Deterministik 100% |
| **Logic Flaws** | Bisa mendeteksi | Terbatas |
| **Konteks Bisnis** | Memahami | Tidak |

### Kapan Menggunakan Masing-masing?

**Gunakan Semgrep untuk:**
- CI/CD pipeline (setiap push/PR)
- Pattern-based vulnerability yang well-defined
- Saat kecepatan dan biaya penting
- Integrasi dengan DevSecOps workflow

**Gunakan LLM SAST untuk:**
- Deep security review
- Code audit manual
- Logic flaws dan business logic vulnerabilities
- Saat membutuhkan penjelasan dan remediation detail
- New vulnerability patterns yang belum ada rule-nya

**Rekomendasi: Gunakan keduanya secara komplementer!**

---

## Variasi Eksperimen

### Eksperimen 1: Bandingkan model DeepSeek V4 Pro vs V4 Flash

```bash
python llm-sast/analyzer.py --dir vulnerable-samples/ --model deepseek-v4-pro --output results/v4_pro.json
python llm-sast/analyzer.py --dir vulnerable-samples/ --model deepseek-v4-flash --output results/v4_flash.json
```

### Eksperimen 2: Tulis custom Semgrep rule untuk setiap vuln

Baca `vulnerable-samples/python/sql_injection.py` dan tulis rule yang tepat untuk mendeteksi setiap pola.

### Eksperimen 3: Tambah kode vulnerable baru

Buat file baru di `vulnerable-samples/` dan lihat apakah kedua tool dapat mendeteksinya.

### Eksperimen 4: Test false positive rate

Modifikasi kode vulnerable menjadi secure, dan periksa apakah tool masih memberi alert.

---

## Troubleshooting

### Error: `DEEPSEEK_API_KEY not found`

```bash
cp .env.example .env
# Edit .env dan isi DEEPSEEK_API_KEY
```

### Error: `semgrep: command not found`

```bash
pip install semgrep
```

### Error: `ModuleNotFoundError: No module named 'openai'`

```bash
uv sync
# atau
pip install openai python-dotenv rich pyyaml
```

### Semgrep scan sangat lambat

```bash
# Tambahkan --timeout dan --max-memory
semgrep --config p/owasp-top-ten --timeout 30 vulnerable-samples/
```

---

## Referensi

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Semgrep Registry](https://semgrep.dev/explore)
- [DeepSeek API](https://platform.deepseek.com/docs/)
- [SANS Top 25 Software Errors](https://www.sans.org/top25-software-errors/)

---

## Lisensi

Dibuat untuk tujuan edukasi. Kode vulnerable hanya untuk latihan keamanan — **jangan gunakan di production!**
