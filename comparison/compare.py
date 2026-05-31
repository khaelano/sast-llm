#!/usr/bin/env python3
"""
Comparison Tool: LLM SAST vs Semgrep
Membandingkan hasil temuan dari kedua tool dan menghasilkan laporan komprehensif
"""

import json
import os
import argparse
from pathlib import Path
from dataclasses import dataclass


@dataclass
class Finding:
    """Representasi unified finding dari berbagai tools"""

    tool: str  # "llm" atau "semgrep"
    file: str
    line_start: int
    line_end: int
    severity: str
    category: str
    cwe_id: str
    title: str
    description: str
    rule_id: str  # Rule ID (untuk semgrep) atau judul (untuk LLM)


def load_llm_results(filepath: str) -> list[Finding]:
    """Load hasil dari LLM SAST analyzer"""
    findings = []

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    for file_result in data.get("results", []):
        filename = os.path.basename(file_result.get("file", ""))
        for vuln in file_result.get("vulnerabilities", []):
            finding = Finding(
                tool="LLM",
                file=filename,
                line_start=vuln.get("line_start", 0),
                line_end=vuln.get("line_end", 0),
                severity=vuln.get("severity", "MEDIUM").upper(),
                category=vuln.get("category", "Unknown"),
                cwe_id=vuln.get("cwe_id", ""),
                title=vuln.get("title", ""),
                description=vuln.get("description", ""),
                rule_id=vuln.get("cwe_id", vuln.get("title", "unknown")),
            )
            findings.append(finding)

    return findings


def load_semgrep_results(filepath: str) -> list[Finding]:
    """Load hasil dari Semgrep scan"""
    findings = []

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    for result in data.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        # Normalisasi severity
        severity_map = {
            "error": "HIGH",
            "warning": "MEDIUM",
            "info": "INFO",
        }
        raw_severity = extra.get("severity", "warning").lower()
        severity = severity_map.get(raw_severity, raw_severity.upper())

        finding = Finding(
            tool="Semgrep",
            file=os.path.basename(result.get("path", "")),
            line_start=result.get("start", {}).get("line", 0),
            line_end=result.get("end", {}).get("line", 0),
            severity=severity,
            category=metadata.get(
                "category", _infer_category(result.get("check_id", ""))
            ),
            cwe_id=metadata.get("cwe", ""),
            title=result.get("check_id", "").split(".")[-1].replace("-", " ").title(),
            description=extra.get("message", ""),
            rule_id=result.get("check_id", ""),
        )
        findings.append(finding)

    return findings


def _infer_category(rule_id: str) -> str:
    """Inferensi kategori dari rule ID"""
    rule_lower = rule_id.lower()
    if "sql" in rule_lower:
        return "SQL Injection"
    elif "xss" in rule_lower or "html" in rule_lower:
        return "Cross-Site Scripting"
    elif "command" in rule_lower or "exec" in rule_lower or "injection" in rule_lower:
        return "Command Injection"
    elif "path" in rule_lower or "traversal" in rule_lower:
        return "Path Traversal"
    elif (
        "secret" in rule_lower or "password" in rule_lower or "credential" in rule_lower
    ):
        return "Hardcoded Secrets"
    elif "jwt" in rule_lower or "auth" in rule_lower:
        return "Authentication Failure"
    elif "crypto" in rule_lower or "hash" in rule_lower or "random" in rule_lower:
        return "Cryptographic Failure"
    elif "pickle" in rule_lower or "deserializ" in rule_lower or "yaml" in rule_lower:
        return "Insecure Deserialization"
    elif "ssrf" in rule_lower or "request" in rule_lower:
        return "SSRF"
    elif "eval" in rule_lower:
        return "Code Injection"
    return "Security Misconfiguration"


def find_overlaps(llm_findings: list[Finding], semgrep_findings: list[Finding]) -> dict:
    """
    Temukan overlap antara temuan LLM dan Semgrep.
    Dua finding dianggap sama jika:
    - File sama
    - Kategori/CWE mirip
    - Nomor baris berdekatan (±10 baris)
    """
    overlaps = []
    llm_only = []
    semgrep_only = list(semgrep_findings)

    used_semgrep = set()

    for llm in llm_findings:
        matched = False
        for i, sg in enumerate(semgrep_findings):
            if i in used_semgrep:
                continue

            # Cek apakah file sama
            if llm.file != sg.file:
                continue

            # Cek apakah kategori/CWE mirip
            category_match = (
                llm.cwe_id and sg.cwe_id and llm.cwe_id == sg.cwe_id
            ) or _categories_similar(llm.category, sg.category)

            if not category_match:
                continue

            # Cek apakah baris berdekatan
            line_diff = abs(llm.line_start - sg.line_start)
            if line_diff <= 15:
                overlaps.append((llm, sg))
                used_semgrep.add(i)
                matched = True
                break

        if not matched:
            llm_only.append(llm)

    semgrep_only = [
        sg for i, sg in enumerate(semgrep_findings) if i not in used_semgrep
    ]

    return {
        "overlaps": overlaps,
        "llm_only": llm_only,
        "semgrep_only": semgrep_only,
    }


def _categories_similar(cat1: str, cat2: str) -> bool:
    """Cek apakah dua kategori merujuk hal yang sama"""
    keywords = {
        "sql": ["sql injection", "sqli", "sql"],
        "xss": ["xss", "cross-site scripting", "html injection"],
        "cmd": ["command injection", "os command", "shell injection", "code injection"],
        "path": ["path traversal", "directory traversal", "path"],
        "secret": ["hardcoded", "credential", "secret", "password", "api key"],
        "auth": [
            "authentication",
            "authorization",
            "jwt",
            "session",
            "idor",
            "access control",
        ],
        "crypto": ["cryptographic", "weak hash", "md5", "sha1", "random"],
        "deser": ["deserialization", "pickle", "yaml"],
        "ssrf": ["ssrf", "server-side request", "request forgery"],
    }

    cat1_lower = cat1.lower()
    cat2_lower = cat2.lower()

    for group_keywords in keywords.values():
        in_cat1 = any(kw in cat1_lower for kw in group_keywords)
        in_cat2 = any(kw in cat2_lower for kw in group_keywords)
        if in_cat1 and in_cat2:
            return True

    return False


def calculate_metrics(analysis: dict, llm_total: int, semgrep_total: int) -> dict:
    """Hitung metrik perbandingan"""
    overlap_count = len(analysis["overlaps"])
    llm_only_count = len(analysis["llm_only"])
    semgrep_only_count = len(analysis["semgrep_only"])

    # Precision & Recall (estimasi)
    # Asumsikan union keduanya sebagai "ground truth" yang mungkin
    union = overlap_count + llm_only_count + semgrep_only_count

    metrics = {
        "llm_total_findings": llm_total,
        "semgrep_total_findings": semgrep_total,
        "overlapping_findings": overlap_count,
        "llm_unique_findings": llm_only_count,
        "semgrep_unique_findings": semgrep_only_count,
        "total_unique_findings": union,
        "agreement_rate": round(overlap_count / max(union, 1) * 100, 1),
        "llm_coverage": round(
            (overlap_count + llm_only_count) / max(union, 1) * 100, 1
        ),
        "semgrep_coverage": round(
            (overlap_count + semgrep_only_count) / max(union, 1) * 100, 1
        ),
    }

    return metrics


def generate_report(
    llm_findings: list[Finding],
    semgrep_findings: list[Finding],
    analysis: dict,
    metrics: dict,
    output_file: str,
):
    """Generate laporan perbandingan komprehensif dalam format HTML"""

    html_content = f"""<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAST Comparison Report: LLM vs Semgrep</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f0f1a; color: #e0e0e0; line-height: 1.6; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        
        h1 {{ font-size: 2rem; background: linear-gradient(135deg, #667eea, #764ba2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 8px; }}
        h2 {{ font-size: 1.3rem; color: #a78bfa; margin: 24px 0 12px; border-bottom: 1px solid #2d2d4e; padding-bottom: 8px; }}
        h3 {{ font-size: 1.1rem; color: #93c5fd; margin-bottom: 8px; }}
        
        .subtitle {{ color: #6b7280; margin-bottom: 30px; }}
        
        /* Stats Grid */
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 30px; }}
        .stat-card {{ background: #1e1e3a; border: 1px solid #2d2d4e; border-radius: 12px; padding: 20px; text-align: center; }}
        .stat-number {{ font-size: 2.5rem; font-weight: 700; line-height: 1; }}
        .stat-label {{ font-size: 0.8rem; color: #6b7280; margin-top: 6px; text-transform: uppercase; letter-spacing: 0.5px; }}
        .stat-llm {{ color: #60a5fa; }}
        .stat-semgrep {{ color: #34d399; }}
        .stat-overlap {{ color: #fbbf24; }}
        .stat-total {{ color: #f87171; }}
        
        /* Comparison Bar */
        .comparison-section {{ background: #1e1e3a; border-radius: 12px; padding: 24px; margin-bottom: 24px; border: 1px solid #2d2d4e; }}
        .bar-container {{ margin: 12px 0; }}
        .bar-label {{ display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 0.9rem; }}
        .bar {{ height: 24px; border-radius: 4px; display: flex; align-items: center; padding-left: 8px; font-size: 0.8rem; font-weight: 600; color: #fff; min-width: 30px; }}
        .bar-llm {{ background: linear-gradient(90deg, #3b82f6, #60a5fa); }}
        .bar-semgrep {{ background: linear-gradient(90deg, #059669, #34d399); }}
        .bar-overlap {{ background: linear-gradient(90deg, #d97706, #fbbf24); }}
        
        /* Tables */
        .findings-table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
        .findings-table th {{ background: #1a1a2e; color: #a78bfa; text-align: left; padding: 10px 12px; border-bottom: 2px solid #2d2d4e; }}
        .findings-table td {{ padding: 8px 12px; border-bottom: 1px solid #1a1a2e; vertical-align: top; }}
        .findings-table tr:hover td {{ background: #1e1e3a; }}
        
        /* Severity badges */
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
        .badge-CRITICAL {{ background: #7c2d12; color: #fca5a5; }}
        .badge-HIGH {{ background: #7f1d1d; color: #fca5a5; }}
        .badge-ERROR {{ background: #7f1d1d; color: #fca5a5; }}
        .badge-MEDIUM {{ background: #78350f; color: #fde68a; }}
        .badge-WARNING {{ background: #78350f; color: #fde68a; }}
        .badge-LOW {{ background: #1e3a5f; color: #93c5fd; }}
        .badge-INFO {{ background: #1e3a5f; color: #93c5fd; }}
        
        /* Tool badges */
        .tool-llm {{ background: #1e3a8a; color: #93c5fd; }}
        .tool-semgrep {{ background: #064e3b; color: #6ee7b7; }}
        
        /* Code snippets */
        .code-snippet {{ background: #0d1117; border: 1px solid #2d2d4e; border-radius: 4px; padding: 6px 10px; font-family: monospace; font-size: 0.8rem; color: #e6db74; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        
        /* Tabs */
        .tabs {{ display: flex; gap: 4px; margin-bottom: 16px; }}
        .tab {{ padding: 8px 16px; border-radius: 6px 6px 0 0; cursor: pointer; font-size: 0.9rem; border: 1px solid #2d2d4e; background: #1a1a2e; color: #6b7280; }}
        .tab.active {{ background: #1e1e3a; color: #a78bfa; border-bottom-color: #1e1e3a; }}
        
        .card {{ background: #1e1e3a; border: 1px solid #2d2d4e; border-radius: 12px; padding: 20px; margin-bottom: 16px; }}
        .overlap-pair {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
        .finding-box {{ background: #0f0f1a; border-radius: 8px; padding: 12px; border-left: 3px solid; }}
        .finding-box-llm {{ border-left-color: #3b82f6; }}
        .finding-box-semgrep {{ border-left-color: #10b981; }}
        
        .chart-container {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 24px; }}
        
        .severity-chart {{ display: flex; flex-direction: column; gap: 8px; }}
        .severity-row {{ display: flex; align-items: center; gap: 12px; }}
        .severity-name {{ width: 80px; font-size: 0.85rem; }}
        .severity-bars {{ display: flex; gap: 4px; flex: 1; align-items: center; }}
        .mini-bar {{ height: 16px; border-radius: 2px; min-width: 4px; }}
        .mini-bar-llm {{ background: #3b82f6; }}
        .mini-bar-semgrep {{ background: #10b981; }}
        .severity-counts {{ font-size: 0.8rem; color: #6b7280; }}
        
        footer {{ text-align: center; color: #374151; margin-top: 40px; padding: 20px; font-size: 0.8rem; }}
    </style>
</head>
<body>
<div class="container">
    <h1>SAST Comparison Report</h1>
    <p class="subtitle">LLM-based SAST vs Semgrep — Analisis Kerentanan Keamanan Kode</p>
    
    <!-- Stats Overview -->
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-number stat-llm">{metrics["llm_total_findings"]}</div>
            <div class="stat-label">LLM Findings</div>
        </div>
        <div class="stat-card">
            <div class="stat-number stat-semgrep">{metrics["semgrep_total_findings"]}</div>
            <div class="stat-label">Semgrep Findings</div>
        </div>
        <div class="stat-card">
            <div class="stat-number stat-overlap">{metrics["overlapping_findings"]}</div>
            <div class="stat-label">Overlapping</div>
        </div>
        <div class="stat-card">
            <div class="stat-number stat-total">{metrics["llm_unique_findings"]}</div>
            <div class="stat-label">LLM Only</div>
        </div>
        <div class="stat-card">
            <div class="stat-number stat-total">{metrics["semgrep_unique_findings"]}</div>
            <div class="stat-label">Semgrep Only</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" style="color: #c084fc;">{metrics["agreement_rate"]}%</div>
            <div class="stat-label">Agreement Rate</div>
        </div>
    </div>
    
    <!-- Coverage Comparison -->
    <div class="comparison-section">
        <h2>Coverage Comparison</h2>
        <div class="bar-container">
            <div class="bar-label"><span>LLM SAST</span><span>{metrics["llm_coverage"]}% ({metrics["llm_total_findings"]} findings)</span></div>
            <div style="background: #1a1a2e; border-radius: 4px; height: 24px; overflow: hidden;">
                <div class="bar bar-llm" style="width: {metrics["llm_coverage"]}%;">{metrics["llm_coverage"]}%</div>
            </div>
        </div>
        <div class="bar-container">
            <div class="bar-label"><span>Semgrep</span><span>{metrics["semgrep_coverage"]}% ({metrics["semgrep_total_findings"]} findings)</span></div>
            <div style="background: #1a1a2e; border-radius: 4px; height: 24px; overflow: hidden;">
                <div class="bar bar-semgrep" style="width: {metrics["semgrep_coverage"]}%;">{metrics["semgrep_coverage"]}%</div>
            </div>
        </div>
        <div class="bar-container">
            <div class="bar-label"><span>Overlapping</span><span>{metrics["agreement_rate"]}% ({metrics["overlapping_findings"]} findings)</span></div>
            <div style="background: #1a1a2e; border-radius: 4px; height: 24px; overflow: hidden;">
                <div class="bar bar-overlap" style="width: {metrics["agreement_rate"]}%;">{metrics["agreement_rate"]}%</div>
            </div>
        </div>
    </div>
    
    <!-- All Findings Table -->
    <div class="comparison-section">
        <h2>Semua Findings</h2>
        <table class="findings-table">
            <thead>
                <tr>
                    <th>Tool</th>
                    <th>File</th>
                    <th>Line</th>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>CWE</th>
                    <th>Title</th>
                </tr>
            </thead>
            <tbody>
                {_generate_all_findings_rows(llm_findings, semgrep_findings)}
            </tbody>
        </table>
    </div>
    
    <!-- Overlapping Findings -->
    <div class="comparison-section">
        <h2>Overlapping Findings ({metrics["overlapping_findings"]} temuan yang sama)</h2>
        {_generate_overlap_cards(analysis["overlaps"])}
    </div>
    
    <!-- LLM Only -->
    <div class="comparison-section">
        <h2>LLM-Only Findings ({metrics["llm_unique_findings"]} temuan unik LLM)</h2>
        <p style="color: #6b7280; margin-bottom: 12px; font-size: 0.9rem;">
            Vulnerability yang ditemukan LLM tapi TIDAK ditemukan Semgrep. 
            Bisa berupa false positives atau temuan kontekstual yang memerlukan pemahaman semantik.
        </p>
        {_generate_findings_table(analysis["llm_only"], "LLM")}
    </div>
    
    <!-- Semgrep Only -->
    <div class="comparison-section">
        <h2>Semgrep-Only Findings ({metrics["semgrep_unique_findings"]} temuan unik Semgrep)</h2>
        <p style="color: #6b7280; margin-bottom: 12px; font-size: 0.9rem;">
            Vulnerability yang ditemukan Semgrep tapi TIDAK ditemukan LLM.
            Biasanya merupakan pattern matching yang tepat sasaran.
        </p>
        {_generate_findings_table(analysis["semgrep_only"], "Semgrep")}
    </div>

    <!-- Analysis Summary -->
    <div class="comparison-section">
        <h2>Analisis & Kesimpulan</h2>
        {_generate_analysis_text(metrics)}
    </div>
    
</div>
<footer>
    Generated by SAST Comparison Tool | LLM SAST vs Semgrep
</footer>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"\nHTML Report disimpan ke: {output_file}")


def _generate_all_findings_rows(llm_findings, semgrep_findings):
    rows = []
    all_findings = [(f, "LLM") for f in llm_findings] + [
        (f, "Semgrep") for f in semgrep_findings
    ]
    all_findings.sort(key=lambda x: (x[0].file, x[0].line_start))

    total = len(all_findings)
    if total > 100:
        print(
            f"  ⚠ {total} total findings — hanya 100 pertama yang ditampilkan di tabel"
        )
    for finding, tool in all_findings[:100]:
        tool_class = "tool-llm" if tool == "LLM" else "tool-semgrep"
        badge_class = f"badge-{finding.severity}"
        rows.append(f"""<tr>
            <td><span class="badge {tool_class}">{tool}</span></td>
            <td>{finding.file}</td>
            <td>{finding.line_start}</td>
            <td><span class="badge {badge_class}">{finding.severity}</span></td>
            <td>{finding.category[:40]}</td>
            <td>{finding.cwe_id}</td>
            <td>{finding.title[:50]}</td>
        </tr>""")

    return (
        "\n".join(rows)
        if rows
        else '<tr><td colspan="7" style="text-align:center;color:#6b7280;">Tidak ada findings</td></tr>'
    )


def _generate_overlap_cards(overlaps):
    if not overlaps:
        return '<p style="color: #6b7280;">Tidak ada overlapping findings.</p>'

    cards = []
    total = len(overlaps)
    if total > 20:
        print(f"  ⚠ {total} overlapping pairs — hanya 20 pertama yang ditampilkan")
    for llm, sg in overlaps[:20]:
        cards.append(f"""
        <div class="card">
            <div class="overlap-pair">
                <div class="finding-box finding-box-llm">
                    <span class="badge tool-llm">LLM</span>
                    <span class="badge badge-{llm.severity}" style="margin-left:6px">{llm.severity}</span>
                    <p style="margin-top:8px;font-weight:600">{llm.title}</p>
                    <p style="color:#6b7280;font-size:0.85rem">{llm.file}:{llm.line_start} | {llm.cwe_id}</p>
                    <p style="font-size:0.85rem;margin-top:6px;color:#d1d5db">{llm.description[:150]}...</p>
                </div>
                <div class="finding-box finding-box-semgrep">
                    <span class="badge tool-semgrep">Semgrep</span>
                    <span class="badge badge-{sg.severity}" style="margin-left:6px">{sg.severity}</span>
                    <p style="margin-top:8px;font-weight:600">{sg.title}</p>
                    <p style="color:#6b7280;font-size:0.85rem">{sg.file}:{sg.line_start} | {sg.cwe_id}</p>
                    <p style="font-size:0.85rem;margin-top:6px;color:#d1d5db">{sg.description[:150]}...</p>
                </div>
            </div>
        </div>""")

    return "\n".join(cards)


def _generate_findings_table(findings, tool):
    if not findings:
        return f'<p style="color: #6b7280;">Tidak ada findings unik untuk {tool}.</p>'

    rows = []
    for f in findings:
        rows.append(f"""<tr>
            <td>{f.file}</td>
            <td>{f.line_start}</td>
            <td><span class="badge badge-{f.severity}">{f.severity}</span></td>
            <td>{f.category}</td>
            <td>{f.cwe_id}</td>
            <td>{f.title[:60]}</td>
            <td style="font-size:0.8rem;color:#9ca3af">{f.description[:100]}...</td>
        </tr>""")

    return f"""<table class="findings-table">
        <thead>
            <tr><th>File</th><th>Line</th><th>Severity</th><th>Category</th><th>CWE</th><th>Title</th><th>Description</th></tr>
        </thead>
        <tbody>{"".join(rows)}</tbody>
    </table>"""


def _generate_analysis_text(metrics):
    llm_cov = metrics["llm_coverage"]
    sg_cov = metrics["semgrep_coverage"]
    agree = metrics["agreement_rate"]

    insights = []

    if llm_cov > sg_cov:
        insights.append(
            f"<li>LLM memiliki <strong>coverage lebih luas</strong> ({llm_cov}% vs {sg_cov}%), karena kemampuannya memahami konteks semantik kode.</li>"
        )
    else:
        insights.append(
            f"<li>Semgrep memiliki <strong>coverage lebih luas</strong> ({sg_cov}% vs {llm_cov}%), karena ruleset yang komprehensif.</li>"
        )

    if agree > 60:
        insights.append(
            f"<li><strong>Tingkat kesepakatan tinggi</strong> ({agree}%), kedua tool konsisten dalam menemukan vulnerability utama.</li>"
        )
    elif agree > 30:
        insights.append(
            f"<li><strong>Tingkat kesepakatan moderat</strong> ({agree}%), ada perbedaan pendekatan yang saling melengkapi.</li>"
        )
    else:
        insights.append(
            f"<li><strong>Tingkat kesepakatan rendah</strong> ({agree}%), kedua tool menemukan jenis vulnerability yang berbeda.</li>"
        )

    insights.append(
        "<li><strong>LLM</strong> unggul dalam: memahami konteks bisnis, menjelaskan dampak, memberikan remediation yang kontekstual, dan menemukan logic flaws.</li>"
    )
    insights.append(
        "<li><strong>Semgrep</strong> unggul dalam: kecepatan scan, konsistensi, tidak ada false positives dari hallucination, reproducibility, dan integrasi CI/CD.</li>"
    )
    insights.append(
        "<li><strong>Rekomendasi</strong>: Gunakan Semgrep untuk CI/CD pipeline (cepat, deterministik), dan LLM untuk deep review saat code review atau audit keamanan.</li>"
    )

    return f"""<ul style="list-style: disc; padding-left: 24px; color: #d1d5db; line-height: 2;">
        {"".join(insights)}
    </ul>"""


def print_comparison_summary(metrics: dict, analysis: dict):
    """Print ringkasan perbandingan ke terminal"""
    print("\n" + "=" * 70)
    print("HASIL PERBANDINGAN: LLM SAST vs SEMGREP")
    print("=" * 70)

    print(f"\n{'Tool':<20} {'Findings':>10} {'Coverage':>10}")
    print("-" * 45)
    print(
        f"{'LLM SAST':<20} {metrics['llm_total_findings']:>10} {metrics['llm_coverage']:>9}%"
    )
    print(
        f"{'Semgrep':<20} {metrics['semgrep_total_findings']:>10} {metrics['semgrep_coverage']:>9}%"
    )
    print("-" * 45)
    print(
        f"{'Overlapping':<20} {metrics['overlapping_findings']:>10} {metrics['agreement_rate']:>9}%"
    )
    print(f"{'LLM Only':<20} {metrics['llm_unique_findings']:>10}")
    print(f"{'Semgrep Only':<20} {metrics['semgrep_unique_findings']:>10}")
    print(f"{'Total Unique':<20} {metrics['total_unique_findings']:>10}")

    print("\n" + "-" * 70)
    print("KELEBIHAN & KEKURANGAN")
    print("-" * 70)

    comparison_table = [
        ("Aspek", "LLM SAST", "Semgrep"),
        ("─" * 20, "─" * 20, "─" * 20),
        ("Kecepatan", "Lambat (API call)", "Sangat Cepat"),
        ("Biaya", "Berbayar per token", "Gratis (OSS)"),
        ("Akurasi Pattern", "Kontekstual", "Rule-based exact"),
        ("False Positives", "Mungkin ada", "Sangat rendah"),
        ("Penjelasan", "Sangat detail", "Terbatas"),
        ("Remediation", "Kontekstual", "Generic"),
        ("Bahasa Support", "Semua bahasa", "40+ bahasa"),
        ("CI/CD Integration", "Kompleks", "Native"),
        ("Offline Support", "Tidak", "Ya"),
        ("Reprodusibilitas", "Tidak konsisten", "Deterministik"),
        ("Logic Flaws", "Bisa deteksi", "Terbatas"),
    ]

    for row in comparison_table:
        print(f"  {row[0]:<22} {row[1]:<22} {row[2]}")

    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Bandingkan hasil LLM SAST vs Semgrep",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh penggunaan:
  python compare.py \\
    --llm results/llm_results.json \\
    --semgrep results/semgrep_full_results.json \\
    --output results/comparison_report.html
        """,
    )
    parser.add_argument("--llm", required=True, help="Path ke hasil LLM SAST (JSON)")
    parser.add_argument("--semgrep", required=True, help="Path ke hasil Semgrep (JSON)")
    parser.add_argument(
        "--output",
        default="results/comparison_report.html",
        help="File output HTML report (default: results/comparison_report.html)",
    )

    args = parser.parse_args()

    print("=" * 70)
    print("SAST COMPARISON TOOL: LLM vs Semgrep")
    print("=" * 70)

    # Load hasil
    print(f"\nLoading LLM results dari: {args.llm}")
    llm_findings = load_llm_results(args.llm)
    print(f"  → {len(llm_findings)} findings dimuat")

    print(f"\nLoading Semgrep results dari: {args.semgrep}")
    semgrep_findings = load_semgrep_results(args.semgrep)
    print(f"  → {len(semgrep_findings)} findings dimuat")

    # Analisis overlap
    print("\nMenganalisis overlap...")
    analysis = find_overlaps(llm_findings, semgrep_findings)

    # Hitung metrik
    metrics = calculate_metrics(analysis, len(llm_findings), len(semgrep_findings))

    # Print summary
    print_comparison_summary(metrics, analysis)

    # Generate HTML report
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    generate_report(llm_findings, semgrep_findings, analysis, metrics, args.output)

    # Save JSON summary
    json_output = args.output.replace(".html", "_metrics.json")
    with open(json_output, "w", encoding="utf-8") as f:
        json.dump(
            {
                "metrics": metrics,
                "llm_only_findings": [
                    {
                        "file": f.file,
                        "line": f.line_start,
                        "severity": f.severity,
                        "category": f.category,
                        "title": f.title,
                    }
                    for f in analysis["llm_only"]
                ],
                "semgrep_only_findings": [
                    {
                        "file": f.file,
                        "line": f.line_start,
                        "severity": f.severity,
                        "category": f.category,
                        "title": f.title,
                    }
                    for f in analysis["semgrep_only"]
                ],
            },
            f,
            indent=2,
        )

    print(f"Metrics JSON disimpan ke: {json_output}")


if __name__ == "__main__":
    main()
