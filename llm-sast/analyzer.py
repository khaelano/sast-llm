#!/usr/bin/env python3
"""
LLM-based SAST Analyzer
Menganalisis kode untuk menemukan vulnerability menggunakan LLM (DeepSeek)
"""

import argparse
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()


@dataclass
class Vulnerability:
    """Representasi sebuah vulnerability yang ditemukan"""

    file: str
    line_start: int
    line_end: int
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # OWASP kategori
    cwe_id: str  # CWE ID (e.g., CWE-89)
    title: str
    description: str
    vulnerable_code: str
    remediation: str
    confidence: str  # HIGH, MEDIUM, LOW


@dataclass
class AnalysisResult:
    """Hasil analisis sebuah file"""

    file: str
    language: str
    total_lines: int
    vulnerabilities: list
    scan_duration_seconds: float
    model_used: str
    tokens_used: int


SYSTEM_PROMPT = """Kamu adalah security expert yang menganalisis kode untuk menemukan kerentanan keamanan (vulnerabilities).

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
Jika tidak ada vulnerability, kembalikan array kosong: []
"""


def detect_language(filepath: str) -> str:
    """Deteksi bahasa pemrograman dari ekstensi file"""
    ext_map = {
        ".py": "Python",
        ".js": "JavaScript",
        ".ts": "TypeScript",
        ".java": "Java",
        ".go": "Go",
        ".rb": "Ruby",
        ".php": "PHP",
        ".cs": "C#",
        ".cpp": "C++",
        ".c": "C",
    }
    ext = Path(filepath).suffix.lower()
    return ext_map.get(ext, "Unknown")


def read_file_with_line_numbers(filepath: str) -> tuple[str, int]:
    """Membaca file dan menambahkan nomor baris"""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    numbered_lines = []
    for i, line in enumerate(lines, 1):
        numbered_lines.append(f"{i:4d} | {line.rstrip()}")

    return "\n".join(numbered_lines), len(lines)


def analyze_file(
    client: OpenAI, filepath: str, model: str = "deepseek-v4-pro"
) -> AnalysisResult:
    """Analisis satu file menggunakan LLM"""
    print(f"  Menganalisis: {filepath}")

    language = detect_language(filepath)
    code_with_lines, total_lines = read_file_with_line_numbers(filepath)

    user_prompt = f"""Analisis kode {language} berikut untuk menemukan kerentanan keamanan:

File: {filepath}
Bahasa: {language}
Total baris: {total_lines}

```{language.lower()}
{code_with_lines}
```

Berikan hasil analisis dalam format JSON array. Setiap elemen adalah satu vulnerability."""

    start_time = time.time()

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
            temperature=0.1,  # Rendah untuk konsistensi
        )

        duration = time.time() - start_time
        if response.usage is not None:
            tokens_used = response.usage.total_tokens
        else:
            tokens_used = 0

        # Parse response
        response_text = response.choices[0].message.content or ""
        parsed = json.loads(response_text)

        # Handle berbagai format response
        if isinstance(parsed, list):
            vulns_raw = parsed
        elif isinstance(parsed, dict):
            # LLM mungkin membungkus dalam key
            vulns_raw = (
                parsed.get("vulnerabilities")
                or parsed.get("findings")
                or parsed.get("results")
                or []
            )
        else:
            vulns_raw = []

        vulnerabilities = []
        for v in vulns_raw:
            try:
                vuln = Vulnerability(
                    file=filepath,
                    line_start=int(v.get("line_start", 0)),
                    line_end=int(v.get("line_end", 0)),
                    severity=v.get("severity", "MEDIUM").upper(),
                    category=v.get("category", "Unknown"),
                    cwe_id=v.get("cwe_id", ""),
                    title=v.get("title", ""),
                    description=v.get("description", ""),
                    vulnerable_code=v.get("vulnerable_code", ""),
                    remediation=v.get("remediation", ""),
                    confidence=v.get("confidence", "MEDIUM").upper(),
                )
                vulnerabilities.append(vuln)
            except (KeyError, ValueError) as e:
                print(f"    Warning: Gagal parse vulnerability: {e}")

        return AnalysisResult(
            file=filepath,
            language=language,
            total_lines=total_lines,
            vulnerabilities=vulnerabilities,
            scan_duration_seconds=round(duration, 2),
            model_used=model,
            tokens_used=tokens_used,
        )

    except json.JSONDecodeError as e:
        print(f"    Error: Gagal parse JSON response: {e}")
        return AnalysisResult(
            file=filepath,
            language=language,
            total_lines=total_lines,
            vulnerabilities=[],
            scan_duration_seconds=0,
            model_used=model,
            tokens_used=0,
        )
    except Exception as e:
        print(f"    Error menganalisis {filepath}: {e}")
        raise


def scan_directory(
    client: OpenAI,
    directory: str,
    extensions: list[str] | None = None,
    model: str = "deepseek-v4-pro",
) -> list[AnalysisResult]:
    """Scan semua file dalam direktori"""
    if extensions is None:
        extensions = [".py", ".js", ".ts", ".java", ".go", ".rb", ".php"]

    results = []
    path = Path(directory)

    files = [f for f in path.rglob("*") if f.is_file() and f.suffix in extensions]

    print(f"\nMenemukan {len(files)} file untuk dianalisis...")
    print("-" * 60)

    for i, filepath in enumerate(files, 1):
        print(f"\n[{i}/{len(files)}] ", end="")
        result = analyze_file(client, str(filepath), model)
        results.append(result)

        # Tampilkan ringkasan
        vuln_count = len(result.vulnerabilities)
        print(
            f"    Ditemukan {vuln_count} vulnerability | "
            f"{result.scan_duration_seconds}s | "
            f"{result.tokens_used} tokens"
        )

    return results


def print_summary(results: list[AnalysisResult]):
    """Tampilkan ringkasan hasil scan"""
    total_files = len(results)
    total_vulns = sum(len(r.vulnerabilities) for r in results)
    total_tokens = sum(r.tokens_used for r in results)
    total_time = sum(r.scan_duration_seconds for r in results)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for result in results:
        for vuln in result.vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1

    print("\n" + "=" * 60)
    print("RINGKASAN HASIL SCAN (LLM SAST)")
    print("=" * 60)
    print(f"Total file dianalisis : {total_files}")
    print(f"Total vulnerability   : {total_vulns}")
    print(f"Total waktu scan      : {total_time:.2f} detik")
    print(f"Total token digunakan : {total_tokens:,}")
    print()
    print("Distribusi Severity:")
    for sev, count in severity_counts.items():
        bar = "█" * count
        print(f"  {sev:<10} : {count:3d} {bar}")

    print()
    print("Detail per File:")
    for result in results:
        if result.vulnerabilities:
            print(f"\n  {result.file}")
            for vuln in result.vulnerabilities:
                print(
                    f"    [{vuln.severity}] Line {vuln.line_start}-{vuln.line_end}: "
                    f"{vuln.title} ({vuln.cwe_id})"
                )


def save_results(results: list[AnalysisResult], output_file: str):
    """Simpan hasil ke file JSON"""
    output = {
        "tool": "LLM SAST Analyzer",
        "scan_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_files": len(results),
        "total_vulnerabilities": sum(len(r.vulnerabilities) for r in results),
        "results": [],
    }

    for result in results:
        result_dict = asdict(result)
        output["results"].append(result_dict)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\nHasil disimpan ke: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="LLM-based SAST Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh penggunaan:
  # Analisis satu file
  python analyzer.py --file vulnerable-samples/python/sql_injection.py

  # Analisis seluruh direktori
  python analyzer.py --dir vulnerable-samples/

  # Gunakan model tertentu dan simpan output
  python analyzer.py --dir vulnerable-samples/ --model deepseek-v4-pro --output results/llm_results.json
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="Path ke file yang akan dianalisis")
    group.add_argument("--dir", help="Path ke direktori yang akan di-scan")

    parser.add_argument(
        "--model",
        default="deepseek-v4-pro",
        choices=["deepseek-v4-flash", "deepseek-v4-pro"],
        help="Model DeepSeek yang digunakan (default: deepseek-v4-pro)",
    )
    parser.add_argument(
        "--output",
        default="results/llm_results.json",
        help="File output JSON (default: results/llm_results.json)",
    )
    parser.add_argument(
        "--extensions",
        nargs="+",
        default=[".py", ".js", ".ts"],
        help="Ekstensi file yang akan di-scan (default: .py .js .ts)",
    )

    args = parser.parse_args()

    # Setup DeepSeek client
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        print("Error: DEEPSEEK_API_KEY environment variable tidak ditemukan!")
        print("Set dengan: export DEEPSEEK_API_KEY='your-api-key'")
        exit(1)

    client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")

    print("=" * 60)
    print("LLM-based SAST Analyzer")
    print(f"Model: {args.model}")
    print("=" * 60)

    # Buat direktori output jika belum ada
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    results = []

    if args.file:
        print(f"\nMenganalisis file: {args.file}")
        result = analyze_file(client, args.file, args.model)
        results = [result]
    else:
        results = scan_directory(
            client, args.dir, extensions=args.extensions, model=args.model
        )

    print_summary(results)
    save_results(results, args.output)


if __name__ == "__main__":
    main()
