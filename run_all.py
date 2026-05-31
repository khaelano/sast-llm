#!/usr/bin/env python3
"""
Master Runner: Jalankan semua scan dan buat laporan perbandingan lengkap
"""

import os
import sys
import json
import subprocess
import argparse
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def run_command(cmd: list, description: str) -> tuple[int, str]:
    """Jalankan command dan kembalikan exit code + output"""
    print(f"\n{'=' * 60}")
    print(f"STEP: {description}")
    print(f"{'=' * 60}")
    print(f"Command: {' '.join(cmd)}")
    print()

    result = subprocess.run(
        cmd, capture_output=False, text=True, cwd=Path(__file__).resolve().parent
    )

    return result.returncode, ""


def check_prerequisites():
    """Cek semua prasyarat tersedia"""
    print("\n" + "=" * 60)
    print("CHECKING PREREQUISITES")
    print("=" * 60)

    issues = []

    # Check Python
    import sys

    print(f"✓ Python {sys.version.split()[0]}")

    # Check DeepSeek API key
    if not os.environ.get("DEEPSEEK_API_KEY"):
        issues.append("DEEPSEEK_API_KEY tidak di-set")
        print("✗ DEEPSEEK_API_KEY: TIDAK ADA")
    else:
        print("✓ DEEPSEEK_API_KEY: Ada")

    # Check Semgrep
    result = subprocess.run(["semgrep", "--version"], capture_output=True, text=True)
    if result.returncode != 0:
        issues.append("Semgrep tidak terinstall (pip install semgrep)")
        print("✗ Semgrep: TIDAK TERINSTALL")
    else:
        print(f"✓ Semgrep: {result.stdout.strip()}")

    # Check required Python packages
    required_packages = ["openai", "rich"]
    for pkg in required_packages:
        try:
            __import__(pkg)
            print(f"✓ Python package '{pkg}': Ada")
        except ImportError:
            issues.append(f"Package Python '{pkg}' tidak terinstall")
            print(f"✗ Python package '{pkg}': TIDAK ADA")

    if issues:
        print("\n⚠ Ada prasyarat yang belum terpenuhi:")
        for issue in issues:
            print(f"  - {issue}")
        return False

    print("\n✓ Semua prasyarat terpenuhi!")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Master runner: LLM SAST + Semgrep + Comparison",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  # Jalankan semua (LLM + Semgrep + Perbandingan)
  python run_all.py

  # Hanya LLM scan
  python run_all.py --only-llm

  # Hanya Semgrep
  python run_all.py --only-semgrep

  # Hanya buat laporan (gunakan hasil yang sudah ada)
  python run_all.py --only-compare
        """,
    )

    parser.add_argument(
        "--model", default="deepseek-v4-pro", help="Model DeepSeek (default: deepseek-v4-pro)"
    )
    parser.add_argument(
        "--target", default="vulnerable-samples/", help="Direktori target"
    )
    parser.add_argument("--output", default="results/", help="Direktori output")
    parser.add_argument(
        "--only-llm", action="store_true", help="Hanya jalankan LLM scan"
    )
    parser.add_argument(
        "--only-semgrep", action="store_true", help="Hanya jalankan Semgrep"
    )
    parser.add_argument(
        "--only-compare", action="store_true", help="Hanya buat laporan perbandingan"
    )
    parser.add_argument(
        "--skip-check", action="store_true", help="Skip pengecekan prasyarat"
    )

    args = parser.parse_args()

    print("\n" + "█" * 60)
    print("  HANDS-ON SAST: LLM vs SEMGREP")
    print("  Static Application Security Testing Workshop")
    print("█" * 60)

    # Buat direktori output
    Path(args.output).mkdir(parents=True, exist_ok=True)

    # Cek prasyarat
    if not args.skip_check and not args.only_compare:
        if not check_prerequisites():
            if not args.only_semgrep:
                print(
                    "\nGunakan --skip-check untuk melewati pengecekan, atau perbaiki masalah di atas."
                )
                sys.exit(1)

    run_llm = not args.only_semgrep and not args.only_compare
    run_semgrep = not args.only_llm and not args.only_compare
    run_compare = not args.only_llm and not args.only_semgrep

    llm_output = f"{args.output}/llm_results.json"
    semgrep_output = f"{args.output}/semgrep_full_results.json"
    comparison_output = f"{args.output}/comparison_report.html"

    # ─────────────────────────────────────────────
    # STEP 1: LLM SAST Scan
    # ─────────────────────────────────────────────
    if run_llm:
        print("\n" + "─" * 60)
        print("LANGKAH 1: LLM SAST Scan")
        print("─" * 60)
        print(f"Model  : {args.model}")
        print(f"Target : {args.target}")
        print(f"Output : {llm_output}")

        rc, _ = run_command(
            [
                sys.executable,
                "llm-sast/analyzer.py",
                "--dir",
                args.target,
                "--model",
                args.model,
                "--output",
                llm_output,
            ],
            "LLM SAST Analyzer",
        )

        if rc != 0:
            print(f"\n⚠ LLM scan selesai dengan exit code {rc}")
        else:
            print("\n✓ LLM scan selesai!")

    # ─────────────────────────────────────────────
    # STEP 2: Semgrep Scan
    # ─────────────────────────────────────────────
    if run_semgrep:
        print("\n" + "─" * 60)
        print("LANGKAH 2: Semgrep Scan")
        print("─" * 60)

        # Cek apakah semgrep tersedia
        semgrep_check = subprocess.run(
            ["which", "semgrep"], capture_output=True, text=True
        )
        if semgrep_check.returncode != 0:
            print("✗ Semgrep tidak tersedia. Lewati step ini.")
            print("  Install: pip install semgrep")
        else:
            rc, _ = run_command(
                [
                    "semgrep",
                    "--config",
                    "p/owasp-top-ten",
                    "--config",
                    "p/python",
                    "--config",
                    "p/javascript",
                    "--config",
                    "p/secrets",
                    "--config",
                    "semgrep-sast/rules/",
                    "--json",
                    "--output",
                    semgrep_output,
                    "--metrics=off",
                    args.target,
                ],
                "Semgrep Multi-Ruleset Scan",
            )

            if rc == 0 or rc == 1:  # Semgrep return 1 jika ada findings
                print("\n✓ Semgrep scan selesai!")
            else:
                print(f"\n⚠ Semgrep selesai dengan exit code {rc}")

    # ─────────────────────────────────────────────
    # STEP 3: Comparison Report
    # ─────────────────────────────────────────────
    if run_compare or args.only_compare:
        print("\n" + "─" * 60)
        print("LANGKAH 3: Comparison Report")
        print("─" * 60)

        # Cek apakah file hasil ada
        llm_exists = Path(llm_output).exists()
        semgrep_exists = Path(semgrep_output).exists()

        if not llm_exists:
            print(f"⚠ File LLM results tidak ditemukan: {llm_output}")
            print("  Jalankan LLM scan terlebih dahulu")

        if not semgrep_exists:
            print(f"⚠ File Semgrep results tidak ditemukan: {semgrep_output}")
            print("  Jalankan Semgrep scan terlebih dahulu")

        if llm_exists and semgrep_exists:
            rc, _ = run_command(
                [
                    sys.executable,
                    "comparison/compare.py",
                    "--llm",
                    llm_output,
                    "--semgrep",
                    semgrep_output,
                    "--output",
                    comparison_output,
                ],
                "Generate Comparison Report",
            )

            if rc == 0:
                print(f"\n✓ Laporan perbandingan dibuat: {comparison_output}")
                print(f"  Buka di browser: open {comparison_output}")

    # Final summary
    print("\n" + "█" * 60)
    print("SELESAI!")
    print("█" * 60)
    print("\nFile yang dihasilkan:")

    result_files = list(Path(args.output).glob("*.json")) + list(
        Path(args.output).glob("*.html")
    )
    for f in sorted(result_files):
        size = f.stat().st_size
        print(f"  {f} ({size:,} bytes)")

    if Path(comparison_output).exists():
        print(f"\n→ Buka laporan: open {comparison_output}")


if __name__ == "__main__":
    main()
